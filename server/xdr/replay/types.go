package replay

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrIntegrity     = errors.New("replay input integrity failure")
	ErrMalformed     = errors.New("malformed replay input")
	ErrStaleBaseline = errors.New("stale replay baseline")
	ErrStaleReview   = errors.New("stale representative-data review")
	ErrRegression    = errors.New("replay regression")
)

type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
)

type Qualification string

const (
	QualificationSyntheticRegression       Qualification = "synthetic-regression"
	QualificationRepresentativeCalibration Qualification = "representative-calibration"
)

type Config struct {
	ManifestPath             string
	RepresentativeReviewPath string
	ReviewAsOf               time.Time
}

type InputChecksums struct {
	ManifestSHA256 string `json:"manifest_sha256"`
	CorpusSHA256   string `json:"corpus_sha256"`
	BaselineSHA256 string `json:"baseline_sha256"`
	WorkflowSHA256 string `json:"representative_workflow_sha256"`
}

type Metrics struct {
	TruePositive         int `json:"true_positive"`
	FalsePositive        int `json:"false_positive"`
	TrueNegative         int `json:"true_negative"`
	FalseNegative        int `json:"false_negative"`
	PrecisionBPS         int `json:"precision_bps"`
	RecallBPS            int `json:"recall_bps"`
	FalsePositiveRateBPS int `json:"false_positive_rate_bps"`
	CompletenessBPS      int `json:"completeness_bps"`
}

type MetricDeltas struct {
	PrecisionBPS         int `json:"precision_bps"`
	RecallBPS            int `json:"recall_bps"`
	FalsePositiveRateBPS int `json:"false_positive_rate_bps"`
	CompletenessBPS      int `json:"completeness_bps"`
}

type AlgorithmResult struct {
	Identity          string  `json:"identity"`
	DescriptorSHA256  string  `json:"descriptor_sha256"`
	RulesSHA256       string  `json:"rules_sha256"`
	Metrics           Metrics `json:"metrics"`
	PromotionEligible bool    `json:"promotion_eligible"`
}

type RepresentativeReview struct {
	ReviewID   string `json:"review_id"`
	Reviewer   string `json:"reviewer"`
	Status     string `json:"status"`
	DataClass  string `json:"data_class"`
	ApprovedAt string `json:"approved_at"`
	ExpiresAt  string `json:"expires_at"`
	SHA256     string `json:"sha256"`
}

type Report struct {
	SchemaVersion                string                `json:"schema_version"`
	ManifestRevision             string                `json:"manifest_revision"`
	Status                       Status                `json:"status"`
	Qualification                Qualification         `json:"qualification"`
	Inputs                       InputChecksums        `json:"inputs"`
	Algorithms                   []AlgorithmResult     `json:"algorithms"`
	Deltas                       MetricDeltas          `json:"deltas"`
	RepresentativeReview         *RepresentativeReview `json:"representative_review"`
	PreventionAuthorized         bool                  `json:"prevention_authorized"`
	CommercialEfficacyAuthorized bool                  `json:"commercial_efficacy_authorized"`
}

type IntegrityError struct{ Path string }

func (e *IntegrityError) Error() string {
	return fmt.Sprintf("replay input checksum mismatch: %s", e.Path)
}
func (e *IntegrityError) Unwrap() error { return ErrIntegrity }

type MalformedError struct {
	Path   string
	Reason string
}

func (e *MalformedError) Error() string {
	return fmt.Sprintf("malformed replay input %s: %s", e.Path, e.Reason)
}
func (e *MalformedError) Unwrap() error { return ErrMalformed }

type RegressionError struct{ Reasons []string }

func (e *RegressionError) Error() string { return fmt.Sprintf("replay regression: %v", e.Reasons) }
func (e *RegressionError) Unwrap() error { return ErrRegression }

type StaleBaselineError struct {
	BaselineRevision string
	ManifestRevision string
}

func (e *StaleBaselineError) Error() string {
	return fmt.Sprintf("baseline revision %q differs from manifest %q", e.BaselineRevision, e.ManifestRevision)
}
func (e *StaleBaselineError) Unwrap() error { return ErrStaleBaseline }

type StaleReviewError struct {
	AsOf       time.Time
	ApprovedAt time.Time
	ExpiresAt  time.Time
}

func (e *StaleReviewError) Error() string {
	return fmt.Sprintf("representative-data review is not valid at %s", e.AsOf.Format(time.RFC3339))
}
func (e *StaleReviewError) Unwrap() error { return ErrStaleReview }
