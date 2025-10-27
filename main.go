/*
Copyright © 2024 i@deifzar.me

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"deifzar/naabum8/cmd"
	"deifzar/naabum8/pkg/log8"
	"syscall"
)

func main() {
	syscall.Umask(0027) // Files: 640, Dirs: 750
	log8.GetLogger()
	cmd.Execute()
}
