package replay

import (
	"fmt"
	"os"
	"time"
)

type reviewDocument struct {
	SchemaVersion    string `json:"schema_version"`
	ReviewID         string `json:"review_id"`
	Reviewer         string `json:"reviewer"`
	Status           string `json:"status"`
	DataClass        string `json:"data_class"`
	ManifestRevision string `json:"manifest_revision"`
	CorpusSHA256     string `json:"corpus_sha256"`
	WorkflowSHA256   string `json:"representative_workflow_sha256"`
	ApprovedAt       string `json:"approved_at"`
	ExpiresAt        string `json:"expires_at"`
}

func loadRepresentativeReview(config Config, inputs loadedInputs) (*RepresentativeReview, error) {
	contents, err := os.ReadFile(config.RepresentativeReviewPath)
	if err != nil {
		return nil, fmt.Errorf("read representative-data review: %w", err)
	}
	var document reviewDocument
	if err := decodeStrict(config.RepresentativeReviewPath, contents, &document); err != nil {
		return nil, err
	}
	if document.SchemaVersion != "lyflow.representative-data-review.v1" || document.ReviewID == "" || document.Reviewer == "" || document.Status != "approved" || document.DataClass != "redacted-representative" {
		return nil, &MalformedError{Path: config.RepresentativeReviewPath, Reason: "review is not an approved redacted representative-data review"}
	}
	if document.ManifestRevision != inputs.manifest.Revision || document.CorpusSHA256 != inputs.manifest.Corpus.SHA256 || document.WorkflowSHA256 != inputs.manifest.Workflow.SHA256 {
		return nil, &MalformedError{Path: config.RepresentativeReviewPath, Reason: "review does not bind the replay inputs"}
	}
	approvedAt, err := time.Parse(time.RFC3339, document.ApprovedAt)
	if err != nil {
		return nil, &MalformedError{Path: config.RepresentativeReviewPath, Reason: "invalid approved_at"}
	}
	expiresAt, err := time.Parse(time.RFC3339, document.ExpiresAt)
	if err != nil || !expiresAt.After(approvedAt) {
		return nil, &MalformedError{Path: config.RepresentativeReviewPath, Reason: "invalid expires_at"}
	}
	if config.ReviewAsOf.IsZero() || config.ReviewAsOf.Before(approvedAt) || config.ReviewAsOf.After(expiresAt) {
		return nil, &StaleReviewError{AsOf: config.ReviewAsOf, ApprovedAt: approvedAt, ExpiresAt: expiresAt}
	}
	return &RepresentativeReview{
		ReviewID: document.ReviewID, Reviewer: document.Reviewer, Status: document.Status,
		DataClass: document.DataClass, ApprovedAt: document.ApprovedAt, ExpiresAt: document.ExpiresAt, SHA256: digest(contents),
	}, nil
}
