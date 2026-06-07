package mobile

import (
	"encoding/json"
	"errors"
	"math"
	"strings"

	genotp "github.com/robby031/genotp-go"
)

const (
	AlgorithmSHA1   = 0
	AlgorithmSHA256 = 1
	AlgorithmSHA512 = 2
)

type TotpHandle struct {
	inner *genotp.TOTP
}

func NewTotpHandle(secretB32 string, algorithm, digits, period int) (*TotpHandle, error) {
	secret, err := decodeBase32(secretB32)
	if err != nil {
		return nil, err
	}
	digits32, err := checkedIntToUint32(digits)
	if err != nil {
		return nil, err
	}
	period64, err := checkedIntToUint64(period)
	if err != nil {
		return nil, err
	}
	t, err := genotp.NewTOTP(secret, genotp.Algorithm(algorithm), digits32, period64)
	if err != nil {
		return nil, err
	}
	return &TotpHandle{inner: t}, nil
}

func (t *TotpHandle) Generate() (string, error) {
	return t.inner.Generate(nil)
}

func (t *TotpHandle) Verify(code string, window int) (bool, error) {
	window64, err := checkedIntToUint64(window)
	if err != nil {
		return false, err
	}
	return t.inner.Verify(code, nil, window64)
}

func (t *TotpHandle) GenerateBound(ctx *ContextHandle) (string, error) {
	return t.inner.GenBound(ctx.inner, nil)
}

func (t *TotpHandle) VerifyBound(code string, ctx *ContextHandle, window int) (bool, error) {
	window64, err := checkedIntToUint64(window)
	if err != nil {
		return false, err
	}
	return t.inner.VerifyBound(code, ctx.inner, nil, window64)
}

func (t *TotpHandle) ClearSecret() {
	t.inner.ClearSecret()
}

type HotpHandle struct {
	inner *genotp.HOTP
}

func NewHotpHandle(secretB32 string, algorithm, digits int) (*HotpHandle, error) {
	secret, err := decodeBase32(secretB32)
	if err != nil {
		return nil, err
	}
	digits32, err := checkedIntToUint32(digits)
	if err != nil {
		return nil, err
	}
	h, err := genotp.NewHOTP(secret, genotp.Algorithm(algorithm), digits32)
	if err != nil {
		return nil, err
	}
	return &HotpHandle{inner: h}, nil
}

func (h *HotpHandle) Generate(counter int64) (string, error) {
	counter64, err := checkedInt64ToUint64(counter)
	if err != nil {
		return "", err
	}
	return h.inner.Generate(counter64)
}

func (h *HotpHandle) Verify(code string, counter int64) (bool, error) {
	counter64, err := checkedInt64ToUint64(counter)
	if err != nil {
		return false, err
	}
	return h.inner.Verify(code, counter64)
}

func (h *HotpHandle) GenerateBound(counter int64, ctx *ContextHandle) (string, error) {
	counter64, err := checkedInt64ToUint64(counter)
	if err != nil {
		return "", err
	}
	return h.inner.GenBound(counter64, ctx.inner)
}

func (h *HotpHandle) VerifyBound(code string, counter int64, ctx *ContextHandle) (bool, error) {
	counter64, err := checkedInt64ToUint64(counter)
	if err != nil {
		return false, err
	}
	return h.inner.VerifyBound(code, counter64, ctx.inner)
}

type ResyncResult struct {
	NewCounter int64
	Valid      bool
}

func (h *HotpHandle) VerifyWithResync(code string, counter, lookAhead int64) (*ResyncResult, error) {
	counter64, err := checkedInt64ToUint64(counter)
	if err != nil {
		return nil, err
	}
	lookAhead64, err := checkedInt64ToUint64(lookAhead)
	if err != nil {
		return nil, err
	}
	newCounter, valid, err := h.inner.VerifyWithResync(code, counter64, lookAhead64)
	if err != nil {
		return nil, err
	}
	if newCounter > math.MaxInt64 {
		return nil, errors.New("counter exceeds int64 range")
	}
	return &ResyncResult{NewCounter: int64(newCounter), Valid: valid}, nil
}

func (h *HotpHandle) ClearSecret() {
	h.inner.ClearSecret()
}

type ContextHandle struct {
	inner *genotp.OtpContext
}

func (c *ContextHandle) IsEmpty() bool {
	return c.inner.IsEmpty()
}

type ContextBuilder struct {
	inner *genotp.OtpContextBuilder
}

func NewContextBuilder() *ContextBuilder {
	return &ContextBuilder{inner: genotp.NewOtpContextBuilder()}
}

func (b *ContextBuilder) SetIP(ip string) *ContextBuilder {
	b.inner.IP(ip)
	return b
}

func (b *ContextBuilder) SetDevice(device string) *ContextBuilder {
	b.inner.Device(device)
	return b
}

func (b *ContextBuilder) SetSession(session string) *ContextBuilder {
	b.inner.Session(session)
	return b
}

func (b *ContextBuilder) SetOrigin(origin string) *ContextBuilder {
	b.inner.Origin(origin)
	return b
}

func (b *ContextBuilder) SetRegion(region string) *ContextBuilder {
	b.inner.Region(region)
	return b
}

func (b *ContextBuilder) SetGeoBucket(bucket string) *ContextBuilder {
	b.inner.GeoBucket(bucket)
	return b
}

func (b *ContextBuilder) SetDistanceClass(class string) *ContextBuilder {
	b.inner.DistanceClass(class)
	return b
}

func (b *ContextBuilder) Build() *ContextHandle {
	return &ContextHandle{inner: b.inner.Build()}
}

type VerifierHandle struct {
	inner *genotp.Verifier
}

func NewVerifierHandle(maxAttempts int) *VerifierHandle {
	maxAttempts32, err := checkedIntToUint32(maxAttempts)
	if err != nil {
		maxAttempts32 = 0
	}
	return &VerifierHandle{inner: genotp.NewVerifier(maxAttempts32)}
}

func (v *VerifierHandle) VerifyWithReplayProtection(code, expected string) bool {
	return v.inner.VerifyWithReplayProtection(code, expected)
}

func (v *VerifierHandle) VerifyWithContext(code, expected string, issued, request *ContextHandle) bool {
	return v.inner.VerifyWithContext(code, expected, issued.inner, request.inner)
}

func (v *VerifierHandle) IsRateLimited() bool {
	return v.inner.IsRateLimited()
}

func (v *VerifierHandle) ResetAttempts() {
	v.inner.ResetAttempts()
}

func (v *VerifierHandle) ClearUsedCodes() {
	v.inner.ClearUsedCodes()
}

type MetricsHandle struct {
	inner *genotp.Metrics
}

func NewMetricsHandle() *MetricsHandle {
	return &MetricsHandle{inner: genotp.NewMetrics()}
}

func (m *MetricsHandle) IncrementHotpGeneration()   { m.inner.IncrementHotpGeneration() }
func (m *MetricsHandle) IncrementHotpVerification() { m.inner.IncrementHotpVerification() }
func (m *MetricsHandle) IncrementTotpGeneration()   { m.inner.IncrementTotpGeneration() }
func (m *MetricsHandle) IncrementTotpVerification() { m.inner.IncrementTotpVerification() }
func (m *MetricsHandle) IncrementError()            { m.inner.IncrementError() }

func (m *MetricsHandle) GetHotpGenerations() int64 {
	return saturatingUint64ToInt64(m.inner.GetHotpGenerations())
}
func (m *MetricsHandle) GetHotpVerifications() int64 {
	return saturatingUint64ToInt64(m.inner.GetHotpVerifications())
}
func (m *MetricsHandle) GetTotpGenerations() int64 {
	return saturatingUint64ToInt64(m.inner.GetTotpGenerations())
}
func (m *MetricsHandle) GetTotpVerifications() int64 {
	return saturatingUint64ToInt64(m.inner.GetTotpVerifications())
}
func (m *MetricsHandle) GetErrors() int64 { return saturatingUint64ToInt64(m.inner.GetErrors()) }
func (m *MetricsHandle) Reset()           { m.inner.Reset() }

func GenerateSecretBase32() (string, error) {
	secret, err := genotp.CreateSecret()
	if err != nil {
		return "", err
	}
	return genotp.EncodeBase32(secret), nil
}

func GenerateSecretBytes() ([]byte, error) {
	return genotp.CreateSecret()
}

func EncodeBase32(data []byte) string {
	return genotp.EncodeBase32(data)
}

func DecodeBase32(s string) ([]byte, error) {
	return decodeBase32(s)
}

func BuildTotpUri(label, secretB32, issuer, algorithm string, digits, period int) string {
	algo := parseAlgoString(algorithm)
	digits32, err := checkedIntToUint32(digits)
	if err != nil {
		return ""
	}
	period64, err := checkedIntToUint64(period)
	if err != nil {
		return ""
	}
	return genotp.NewOtpAuthUri(genotp.TotpType, label, secretB32).
		Issuer(issuer).
		Algorithm(algo).
		Digits(digits32).
		Period(period64).
		Build()
}

func BuildHotpUri(label, secretB32, issuer, algorithm string, digits int, counter int64) string {
	algo := parseAlgoString(algorithm)
	digits32, err := checkedIntToUint32(digits)
	if err != nil {
		return ""
	}
	counter64, err := checkedInt64ToUint64(counter)
	if err != nil {
		return ""
	}
	return genotp.NewOtpAuthUri(genotp.HotpType, label, secretB32).
		Issuer(issuer).
		Algorithm(algo).
		Digits(digits32).
		Counter(counter64).
		Build()
}

func BuildOtpAuthMigrationUri(accountsJSON string, version, batchSize, batchIndex, batchID int) (string, error) {
	var accounts []genotp.OtpAuthMigrationAccount
	if err := json.Unmarshal([]byte(accountsJSON), &accounts); err != nil {
		return "", err
	}
	if version < 0 || batchSize < 0 || batchIndex < 0 || batchID < 0 {
		return "", errors.New("migration metadata must be non-negative")
	}
	if version > math.MaxInt32 || batchSize > math.MaxInt32 || batchIndex > math.MaxInt32 || batchID > math.MaxInt32 {
		return "", errors.New("migration metadata exceeds int32 range")
	}

	return genotp.BuildOtpAuthMigrationURI(accounts, &genotp.OtpAuthMigrationOptions{
		Version:    int32(version),
		BatchSize:  int32(batchSize),
		BatchIndex: int32(batchIndex),
		BatchID:    int32(batchID),
	})
}

func ParseOtpAuthMigrationUri(uri string) (string, error) {
	payload, err := genotp.ParseOtpAuthMigrationURI(uri)
	if err != nil {
		return "", err
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	dst := make([]byte, len(s)*5/8+1)
	n, err := genotp.DecodeBase32(dst, s)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func parseAlgoString(s string) genotp.Algorithm {
	switch strings.ToUpper(s) {
	case "SHA256":
		return genotp.SHA256
	case "SHA512":
		return genotp.SHA512
	default:
		return genotp.SHA1
	}
}

func checkedIntToUint32(value int) (uint32, error) {
	if value < 0 {
		return 0, errors.New("value out of uint32 range")
	}
	if uint64(value) > math.MaxUint32 {
		return 0, errors.New("value out of uint32 range")
	}
	return uint32(value), nil
}

func checkedIntToUint64(value int) (uint64, error) {
	if value < 0 {
		return 0, errors.New("value out of uint64 range")
	}
	return uint64(value), nil
}

func checkedInt64ToUint64(value int64) (uint64, error) {
	if value < 0 {
		return 0, errors.New("value out of uint64 range")
	}
	return uint64(value), nil
}

func saturatingUint64ToInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}
