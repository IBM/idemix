/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

// SumOfG1ProductsPairwiseForBench exposes the internal pairwise Mul2+Add loop to
// bbs_test (external test package) so BenchmarkSumOfG1ProductsCrossover in
// benchmark_test.go can compare it directly against curve.MultiScalarMul.
var SumOfG1ProductsPairwiseForBench = sumOfG1Products
