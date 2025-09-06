package logging

import (
	"log"
	"os"
)

// Logger wraps the standard logger
type Logger struct {
	*log.Logger
}

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return &Logger{
		Logger: log.New(os.Stdout, "", log.LstdFlags|log.Lshortfile),
	}
}

// Debug logs a debug message
func (l *Logger) Debug(v ...interface{}) {
	l.Printf("[DEBUG] %v", v...)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, v ...interface{}) {
	l.Printf("[DEBUG] "+format, v...)
}

// Info logs an info message
func (l *Logger) Info(v ...interface{}) {
	l.Printf("[INFO] %v", v...)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, v ...interface{}) {
	l.Printf("[INFO] "+format, v...)
}

// Warn logs a warning message
func (l *Logger) Warn(v ...interface{}) {
	l.Printf("[WARN] %v", v...)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, v ...interface{}) {
	l.Printf("[WARN] "+format, v...)
}

// Error logs an error message
func (l *Logger) Error(v ...interface{}) {
	l.Printf("[ERROR] %v", v...)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.Printf("[ERROR] "+format, v...)
}

// Fatal logs a fatal error message and exits
func (l *Logger) Fatal(v ...interface{}) {
	l.Fatalf("[FATAL] %v", v...)
}

// Fatalf logs a formatted fatal error message and exits
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.Fatalf("[FATAL] "+format, v...)
}
