/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package grpclog

import "gitee.com/zhaochuninhefei/gmgo/grpc/internal/grpclog"

// Logger mimics golang's standard Logger as an interface.
//
// Deprecated: use LoggerV2.
type Logger interface {
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Fatalln(args ...any)
	Print(args ...any)
	Printf(format string, args ...any)
	Println(args ...any)
}

// SetLogger sets the logger that is used in grpc. Call only from
// init() functions.
//
// Deprecated: use SetLoggerV2.
func SetLogger(l Logger) {
	grpclog.Logger = &loggerWrapper{Logger: l}
}

// loggerWrapper wraps Logger into a LoggerV2.
type loggerWrapper struct {
	Logger
}

func (g *loggerWrapper) Info(args ...any) {
	g.Logger.Print(args...)
}

func (g *loggerWrapper) Infoln(args ...any) {
	g.Logger.Println(args...)
}

func (g *loggerWrapper) Infof(format string, args ...any) {
	g.Logger.Printf(format, args...)
}

func (g *loggerWrapper) Warning(args ...any) {
	g.Logger.Print(args...)
}

func (g *loggerWrapper) Warningln(args ...any) {
	g.Logger.Println(args...)
}

func (g *loggerWrapper) Warningf(format string, args ...any) {
	g.Logger.Printf(format, args...)
}

func (g *loggerWrapper) Error(args ...any) {
	g.Logger.Print(args...)
}

func (g *loggerWrapper) Errorln(args ...any) {
	g.Logger.Println(args...)
}

func (g *loggerWrapper) Errorf(format string, args ...any) {
	g.Logger.Printf(format, args...)
}

func (g *loggerWrapper) V(l int) bool {
	// Returns true for all verbose level.
	return true
}
