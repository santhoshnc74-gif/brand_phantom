"""
services/dataset_service.py
Service layer for dataset validation, streaming import, cleaning reports,
paginated preview, and background ML training execution in BrandSentinel.
"""

import os
import csv
import json
import uuid
import hashlib
import logging
import threading
from datetime import datetime
from urllib.parse import urlparse
from sqlalchemy import func

from db.database import SessionLocal
from db.models import Dataset, DatasetRecord, MLTrainingJob, MLModelArtifact
from ml.url_features import normalize_url, extract_domain_and_registrable
from ml.train_phishing import train_phishing_pipeline
from ml.predict_phishing import clear_model_cache

logger = logging.getLogger("services.dataset_service")

# Storage directory for imported datasets outside static/
DATASETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "managed_datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)

def compute_file_hash_and_size(file_path: str):
    """Computes SHA-256 hash and size in bytes."""
    hasher = hashlib.sha256()
    size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size

def validate_and_import_csv(file_path: str, organization_id: str, original_filename: str = None) -> dict:
    """
    Validates, cleans, deduplicates, and imports a phishing URL CSV dataset.
    Idempotent: If dataset with same hash exists in this organization, returns existing record.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    filename = original_filename or os.path.basename(file_path)
    file_hash, file_size = compute_file_hash_and_size(file_path)

    db = SessionLocal()
    try:
        # Check idempotency
        existing = db.query(Dataset).filter(
            Dataset.organization_id == organization_id,
            Dataset.file_hash == file_hash
        ).first()

        if existing:
            cleaning_report = {}
            try:
                cleaning_report = json.loads(existing.cleaning_report_json) if existing.cleaning_report_json else {}
            except Exception:
                pass
            return {
                "dataset_id": existing.id,
                "name": existing.name,
                "filename": existing.filename,
                "file_hash": existing.file_hash,
                "already_imported": True,
                "total_rows": existing.total_rows,
                "accepted_rows": existing.accepted_rows,
                "rejected_rows": existing.rejected_rows,
                "duplicate_rows": existing.duplicate_rows,
                "conflicting_rows": existing.conflicting_rows,
                "legitimate_count": existing.legitimate_count,
                "phishing_count": existing.phishing_count,
                "cleaning_report": cleaning_report
            }

        # Validate CSV structure and stream parse
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                raise ValueError("The provided file is empty.")

            # Identify URL and label columns
            header_lower = [h.strip().lower() for h in header]
            url_idx = None
            label_idx = None

            for i, col in enumerate(header_lower):
                if col in ("url", "urls", "website", "website_url"):
                    url_idx = i
                    break
            if url_idx is None and "url" in header_lower:
                url_idx = header_lower.index("url")

            for i, col in enumerate(header_lower):
                if col in ("label", "target", "class", "is_phishing", "result"):
                    label_idx = i
                    break

            if url_idx is None:
                raise ValueError("Missing required 'URL' column in CSV header.")
            if label_idx is None:
                raise ValueError("Missing required 'label' column in CSV header.")

            total_rows = 0
            rejected_rows = 0
            
            # Map normalized URL to set of labels to detect conflicts and duplicates
            # Store first occurrence info
            url_to_info = {} # norm_url -> {"raw_url": ..., "labels": set(), "first_idx": int, "domain": str}
            
            for row in reader:
                total_rows += 1
                if len(row) <= max(url_idx, label_idx):
                    rejected_rows += 1
                    continue
                raw_url = row[url_idx].strip()
                raw_label = row[label_idx].strip()

                if not raw_url or raw_label not in ("0", "1"):
                    rejected_rows += 1
                    continue

                label_val = int(raw_label)
                norm_url = normalize_url(raw_url)
                if not norm_url:
                    rejected_rows += 1
                    continue

                host, _ = extract_domain_and_registrable(norm_url)
                if not host:
                    rejected_rows += 1
                    continue

                if norm_url not in url_to_info:
                    url_to_info[norm_url] = {
                        "raw_url": raw_url,
                        "domain": host,
                        "labels": {label_val},
                        "first_label": label_val,
                        "first_idx": total_rows,
                        "occurrences": 1
                    }
                else:
                    url_to_info[norm_url]["labels"].add(label_val)
                    url_to_info[norm_url]["occurrences"] += 1

        # Calculate counts
        unique_urls = len(url_to_info)
        # Duplicate rows: repeated occurrences with matching labels
        duplicate_rows = sum(info["occurrences"] - 1 for info in url_to_info.values() if len(info["labels"]) == 1)
        
        # Conflicting rows (different labels for same URL) -> quarantine both
        conflicting_count = 0
        accepted_records = []
        legitimate_count = 0
        phishing_count = 0

        for norm_url, info in url_to_info.items():
            if len(info["labels"]) > 1:
                # Conflicting label detected! Quarantine
                conflicting_count += info["occurrences"]
            else:
                lbl = info["first_label"]
                accepted_records.append({
                    "url": norm_url,
                    "domain": info["domain"],
                    "label": lbl,
                    "label_name": "Legitimate" if lbl == 1 else "Phishing",
                    "row_index": info["first_idx"]
                })
                if lbl == 1:
                    legitimate_count += 1
                elif lbl == 0:
                    phishing_count += 1

        accepted_rows = len(accepted_records)

        cleaning_report = {
            "total_source_rows": total_rows,
            "accepted_rows": accepted_rows,
            "rejected_rows": rejected_rows,
            "duplicate_rows": duplicate_rows,
            "conflicting_rows": conflicting_count,
            "legitimate_count": legitimate_count,
            "phishing_count": phishing_count,
            "unique_urls": unique_urls,
            "file_hash": file_hash,
            "file_size_bytes": file_size,
            "imported_at": datetime.utcnow().isoformat()
        }

        # Copy or persist managed copy if uploaded
        dest_filename = f"{uuid.uuid4()}_{filename}"
        dest_path = os.path.join(DATASETS_DIR, dest_filename)
        if os.path.abspath(file_path) != os.path.abspath(dest_path):
            import shutil
            shutil.copy2(file_path, dest_path)
        else:
            dest_path = file_path

        # Create Dataset in DB
        new_dataset = Dataset(
            organization_id=organization_id,
            name=filename,
            filename=filename,
            file_path=dest_path,
            file_hash=file_hash,
            file_size_bytes=file_size,
            total_rows=total_rows,
            accepted_rows=accepted_rows,
            rejected_rows=rejected_rows,
            duplicate_rows=duplicate_rows,
            conflicting_rows=conflicting_count,
            legitimate_count=legitimate_count,
            phishing_count=phishing_count,
            cleaning_report_json=json.dumps(cleaning_report)
        )
        db.add(new_dataset)
        db.commit()

        # Insert dataset records in batches (insert first 10,000 for high-performance preview)
        records_to_insert = []
        preview_limit = min(len(accepted_records), 10000)
        for i in range(preview_limit):
            rec = accepted_records[i]
            records_to_insert.append(
                DatasetRecord(
                    dataset_id=new_dataset.id,
                    organization_id=organization_id,
                    row_index=rec["row_index"],
                    url=rec["url"],
                    domain=rec["domain"],
                    label=rec["label"],
                    label_name=rec["label_name"],
                    is_duplicate=False
                )
            )

        db.bulk_save_objects(records_to_insert)
        db.commit()

        return {
            "dataset_id": new_dataset.id,
            "name": new_dataset.name,
            "filename": new_dataset.filename,
            "file_hash": new_dataset.file_hash,
            "already_imported": False,
            "total_rows": total_rows,
            "accepted_rows": accepted_rows,
            "rejected_rows": rejected_rows,
            "duplicate_rows": duplicate_rows,
            "conflicting_rows": conflicting_count,
            "legitimate_count": legitimate_count,
            "phishing_count": phishing_count,
            "cleaning_report": cleaning_report
        }
    finally:
        db.close()

def get_dataset_preview(dataset_id: str, organization_id: str, page: int = 1, page_size: int = 20) -> dict:
    """Returns paginated preview of imported dataset rows."""
    db = SessionLocal()
    try:
        dataset = db.query(Dataset).filter(
            Dataset.id == dataset_id,
            Dataset.organization_id == organization_id
        ).first()

        if not dataset:
            raise ValueError("Dataset not found or access denied.")

        total_records = db.query(func.count(DatasetRecord.id)).filter(
            DatasetRecord.dataset_id == dataset_id
        ).scalar() or 0

        offset = (page - 1) * page_size
        records = db.query(DatasetRecord).filter(
            DatasetRecord.dataset_id == dataset_id
        ).order_by(DatasetRecord.row_index.asc()).offset(offset).limit(page_size).all()

        rows = []
        for r in records:
            rows.append({
                "id": r.id,
                "row_index": r.row_index,
                "url": r.url,
                "domain": r.domain,
                "label": r.label,
                "label_name": r.label_name
            })

        return {
            "dataset_id": dataset.id,
            "dataset_name": dataset.name,
            "total_records": dataset.accepted_rows,
            "preview_total": total_records,
            "page": page,
            "page_size": page_size,
            "rows": rows
        }
    finally:
        db.close()

def recover_interrupted_jobs():
    """Marks any lingering 'running' or 'pending' jobs as interrupted on server restart."""
    db = SessionLocal()
    try:
        interrupted = db.query(MLTrainingJob).filter(
            MLTrainingJob.status.in_(["running", "pending"])
        ).all()
        for job in interrupted:
            job.status = "failed"
            job.error_message = "Training job interrupted by server restart. You may retry training."
            job.completed_at = datetime.utcnow()
        if interrupted:
            db.commit()
            logger.info(f"Marked {len(interrupted)} interrupted ML training jobs as failed.")
    except Exception as e:
        logger.error(f"Error recovering interrupted jobs: {e}")
        db.rollback()
    finally:
        db.close()

def _run_training_job_worker(job_id: str, dataset_id: str, organization_id: str):
    """Background worker executing model training pipeline."""
    logger.info(f"Starting background training worker for Job {job_id}...")
    db = SessionLocal()
    try:
        job = db.query(MLTrainingJob).filter(MLTrainingJob.id == job_id).first()
        if not job:
            logger.error(f"Job {job_id} not found.")
            return

        dataset = db.query(Dataset).filter(Dataset.id == dataset_id).first()
        if not dataset:
            job.status = "failed"
            job.error_message = "Associated dataset not found."
            job.completed_at = datetime.utcnow()
            db.commit()
            return

        job.status = "running"
        job.started_at = datetime.utcnow()
        job.current_stage = "loading_dataset"
        job.progress_percent = 5
        db.commit()

        # Stream load all clean unique rows from managed CSV file
        csv_path = dataset.file_path
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Managed dataset file not found at: {csv_path}")

        cleaned_records = []
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader)
            header_lower = [h.strip().lower() for h in header]
            url_idx = header_lower.index("url")
            label_idx = header_lower.index("label")

            seen_urls = set()
            for row in reader:
                if len(row) <= max(url_idx, label_idx):
                    continue
                url = row[url_idx].strip()
                label = row[label_idx].strip()
                if not url or label not in ("0", "1"):
                    continue
                norm = normalize_url(url)
                if not norm or norm in seen_urls:
                    continue
                seen_urls.add(norm)
                cleaned_records.append({
                    "url": norm,
                    "label": int(label)
                })

        logger.info(f"Loaded {len(cleaned_records)} unique clean records for training.")

        def progress_callback(stage, percent, details):
            # Update DB periodically inside worker
            try:
                worker_db = SessionLocal()
                w_job = worker_db.query(MLTrainingJob).filter(MLTrainingJob.id == job_id).first()
                if w_job:
                    w_job.current_stage = stage
                    w_job.progress_percent = percent
                    worker_db.commit()
                worker_db.close()
            except Exception as pe:
                logger.warning(f"Failed to record progress: {pe}")

        # Train ML Pipeline
        train_result = train_phishing_pipeline(
            cleaned_records=cleaned_records,
            dataset_hash=dataset.file_hash,
            progress_callback=progress_callback
        )

        model_version = train_result["model_version"]
        model_type = train_result["model_type"]
        artifact_path = train_result["artifact_path"]
        metrics = train_result["test_metrics"]

        # Atomic Activation: deactivate old models for this org, activate new model
        db.query(MLModelArtifact).filter(
            MLModelArtifact.organization_id == organization_id
        ).update({"is_active": False})

        new_artifact = MLModelArtifact(
            organization_id=organization_id,
            model_version=model_version,
            dataset_id=dataset_id,
            model_type=model_type,
            artifact_path=artifact_path,
            metrics_json=json.dumps(train_result["bundle_metadata"]),
            feature_extractor_version="1.0.0",
            decision_threshold=0.5,
            is_active=True
        )
        db.add(new_artifact)

        job.status = "completed"
        job.current_stage = "ready"
        job.progress_percent = 100
        job.model_version = model_version
        job.metrics_json = json.dumps(metrics)
        job.completed_at = datetime.utcnow()
        db.commit()

        # Clear active model cache so newly activated model loads on next prediction
        clear_model_cache()
        logger.info(f"Training Job {job_id} completed successfully. Active model: {model_version}")

    except Exception as e:
        logger.error(f"Training worker failed: {e}", exc_info=True)
        try:
            job = db.query(MLTrainingJob).filter(MLTrainingJob.id == job_id).first()
            if job:
                job.status = "failed"
                job.error_message = str(e)
                job.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()

def start_training_job(organization_id: str, dataset_id: str = None) -> dict:
    """Spawns background training job for the organization."""
    db = SessionLocal()
    try:
        # Check active training job
        running_job = db.query(MLTrainingJob).filter(
            MLTrainingJob.organization_id == organization_id,
            MLTrainingJob.status.in_(["pending", "running"])
        ).first()

        if running_job:
            return {
                "job_id": running_job.id,
                "status": running_job.status,
                "stage": running_job.current_stage,
                "progress_percent": running_job.progress_percent,
                "message": "A training job is already in progress."
            }

        # Find target dataset
        if dataset_id:
            dataset = db.query(Dataset).filter(
                Dataset.id == dataset_id,
                Dataset.organization_id == organization_id
            ).first()
        else:
            dataset = db.query(Dataset).filter(
                Dataset.organization_id == organization_id
            ).order_by(Dataset.created_at.desc()).first()

        if not dataset:
            raise ValueError("No dataset found for this organization. Please import the dataset first.")

        new_job = MLTrainingJob(
            organization_id=organization_id,
            dataset_id=dataset.id,
            status="pending",
            current_stage="queued",
            progress_percent=0
        )
        db.add(new_job)
        db.commit()
        job_id = new_job.id

        # Spawn background thread
        worker_thread = threading.Thread(
            target=_run_training_job_worker,
            args=(job_id, dataset.id, organization_id),
            daemon=True
        )
        worker_thread.start()

        return {
            "job_id": job_id,
            "status": "pending",
            "stage": "queued",
            "progress_percent": 0,
            "message": "Training job queued successfully."
        }
    finally:
        db.close()

def get_job_status(job_id: str, organization_id: str) -> dict:
    """Returns status, stage, progress, and metrics for a training job."""
    db = SessionLocal()
    try:
        job = db.query(MLTrainingJob).filter(
            MLTrainingJob.id == job_id,
            MLTrainingJob.organization_id == organization_id
        ).first()

        if not job:
            raise ValueError("Training job not found.")

        metrics = {}
        try:
            metrics = json.loads(job.metrics_json) if job.metrics_json else {}
        except Exception:
            pass

        return {
            "job_id": job.id,
            "status": job.status,
            "stage": job.current_stage,
            "progress_percent": job.progress_percent,
            "error_message": job.error_message,
            "model_version": job.model_version,
            "metrics": metrics,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None
        }
    finally:
        db.close()

def get_active_model_info(organization_id: str) -> dict:
    """Returns active model details and status."""
    db = SessionLocal()
    try:
        active = db.query(MLModelArtifact).filter(
            MLModelArtifact.organization_id == organization_id,
            MLModelArtifact.is_active == True
        ).first()

        running_job = db.query(MLTrainingJob).filter(
            MLTrainingJob.organization_id == organization_id,
            MLTrainingJob.status.in_(["pending", "running"])
        ).first()

        if running_job:
            status = "Training"
        elif active:
            status = "Ready"
        else:
            # Check if dataset exists
            ds_exists = db.query(Dataset).filter(Dataset.organization_id == organization_id).first()
            status = "Training required" if ds_exists else "Not trained"

        if not active:
            return {
                "status": status,
                "is_active": False,
                "model_version": None,
                "model_type": None,
                "metrics": None
            }

        metrics = {}
        try:
            metrics = json.loads(active.metrics_json) if active.metrics_json else {}
        except Exception:
            pass

        return {
            "status": status,
            "is_active": True,
            "model_version": active.model_version,
            "model_type": active.model_type,
            "artifact_path": active.artifact_path,
            "decision_threshold": active.decision_threshold,
            "metrics": metrics
        }
    finally:
        db.close()
