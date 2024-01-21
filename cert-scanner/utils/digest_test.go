package utils

import (
	"testing"

	"github.com/sgargan/cert-scanner-darkly/types"
	"github.com/stretchr/testify/suite"
)

type DigestTests struct {
	suite.Suite
}

func (t *DigestTests) TestEmptyDigests() {
	t.Equal("ef46db3751d8e999", Digest(types.Labels{}))
}

func (t *DigestTests) TestDeterministicDigests() {
	labels := types.Labels{"foo": "bar", "baz": "bang"}
	t.Equal(Digest(labels), Digest(labels))
}

func (t *DigestTests) TestOrderIndependentDigests() {
	// verify that the arbitrary map ordering does not effect digest
	labels := types.Labels{"foo": "bar", "baz": "bang"}
	reordered := types.Labels{"baz": "bang", "foo": "bar"}
	t.Equal(Digest(labels), Digest(reordered))
}

func TestDigestTests(t *testing.T) {
	suite.Run(t, &DigestTests{})
}
