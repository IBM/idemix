/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"log"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger defines the logging interface required by msp.
// This interface is compatible with the Go SDK log package and common logging facades.
type Logger interface {
	Debug(args ...any)
	Debugf(format string, args ...any)
	Errorf(format string, args ...any)
	IsEnabledFor(level zapcore.Level) bool
}

// defaultLogger is a simple logger implementation that wraps zap.SugaredLogger
// and satisfies the Logger interface.
type defaultLogger struct {
	*zap.SugaredLogger
	core zapcore.Core
}

// IsEnabledFor checks if the logger is enabled for the given level
func (l *defaultLogger) IsEnabledFor(level zapcore.Level) bool {
	return l.core.Enabled(level)
}

// newDefaultLogger creates a new logger instance compatible with the Logger interface.
// It uses zap for structured logging with a development configuration.
func newDefaultLogger(name string) Logger {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	zapLogger, err := config.Build()
	if err != nil {
		// Fallback to standard log if zap initialization fails
		log.Printf("failed to initialize zap logger: %v, using standard logger", err)

		return &stdLogger{prefix: name}
	}

	return &defaultLogger{
		SugaredLogger: zapLogger.Sugar().Named(name),
		core:          zapLogger.Core(),
	}
}

// stdLogger is a fallback logger using Go's standard log package
type stdLogger struct {
	prefix string
}

func (l *stdLogger) Debug(args ...any) {
	log.Println(append([]any{l.prefix + " [DEBUG]"}, args...)...)
}

func (l *stdLogger) Debugf(format string, args ...any) {
	log.Printf(l.prefix+" [DEBUG] "+format, args...)
}

func (l *stdLogger) Errorf(format string, args ...any) {
	log.Printf(l.prefix+" [ERROR] "+format, args...)
}

func (l *stdLogger) IsEnabledFor(level zapcore.Level) bool {
	return true // Standard logger always logs
}
