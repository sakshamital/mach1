"""
YOUR SENTINEL — Model training script.

Loads scams.csv + user examples, fine-tunes ai4bharat/indic-bert,
optionally pushes to HuggingFace Hub.
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path

logger = logging.getLogger("SENTINEL.TRAINING")
logging.basicConfig(level=logging.INFO)


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune Indic-BERT on scam dataset")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--output-dir", default="training/model_output")
    parser.add_argument("--push-hub", action="store_true")
    parser.add_argument("--hub-model-id", default="")
    args = parser.parse_args()

    try:
        from training.dataset import load_full_dataset, to_huggingface_format
        scams, safes = load_full_dataset()
        if len(scams) < 10:
            logger.error("Insufficient training data")
            return
        records = to_huggingface_format(scams, safes)
        logger.info("Training on %d records", len(records))

        try:
            from datasets import Dataset
            import torch
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
                Trainer,
                TrainingArguments,
            )
        except ImportError:
            logger.error("Install: pip install transformers datasets torch accelerate")
            return

        texts = [r["text"] for r in records]
        labels = [r["label"] for r in records]
        ds = Dataset.from_dict({"text": texts, "label": labels})
        ds = ds.train_test_split(test_size=0.1, seed=42)

        model_name = os.getenv("HUGGINGFACE_MODEL", "ai4bharat/indic-bert")
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForSequenceClassification.from_pretrained(
            model_name, num_labels=2
        )

        def tokenize(batch):
            return tokenizer(
                batch["text"], truncation=True, padding="max_length", max_length=256
            )

        tokenized = ds.map(tokenize, batched=True)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        training_args = TrainingArguments(
            output_dir=str(output_dir),
            num_train_epochs=args.epochs,
            per_device_train_batch_size=args.batch_size,
            per_device_eval_batch_size=args.batch_size,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            logging_steps=50,
        )

        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=tokenized["train"],
            eval_dataset=tokenized["test"],
            tokenizer=tokenizer,
        )
        trainer.train()
        trainer.save_model(str(output_dir))
        tokenizer.save_pretrained(str(output_dir))
        logger.info("Model saved to %s", output_dir)

        if args.push_hub:
            hub_id = args.hub_model_id or os.getenv("HF_HUB_MODEL_ID", "")
            token = os.getenv("HUGGINGFACE_API_KEY", "")
            if hub_id and token and token != "YOUR_KEY_HERE":
                model.push_to_hub(hub_id, token=token)
                tokenizer.push_to_hub(hub_id, token=token)
                logger.info("Pushed to HuggingFace Hub: %s", hub_id)
            else:
                logger.warning("Set --hub-model-id and HUGGINGFACE_API_KEY to push")
    except Exception as exc:
        logger.error("Training failed: %s", exc)
        raise


if __name__ == "__main__":
    main()
