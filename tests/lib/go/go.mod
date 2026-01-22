// Copyright 2024-2025 Politecnico di Torino
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

module test_pretty_verifier

go 1.25.0

require (
	github.com/cilium/ebpf v0.20.0
	github.com/netgroup-polito/pretty-verifier/lib/go v0.0.0-00010101000000-000000000000
)

require golang.org/x/sys v0.37.0 // indirect

replace github.com/netgroup-polito/pretty-verifier/lib/go => ../../../lib/go
