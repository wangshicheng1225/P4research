#!/bin/bash

# Copyright 2013-present Barefoot Networks, Inc. 
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source $THIS_DIR/../../env.sh

TARGET=ping_switch
TARGET_SRC=$TARGET.p4
TARGET_JSON=$TARGET.json

p4c-bm2-ss -o $TARGET_JSON --p4v 14 ./p4src/$TARGET_SRC

sudo simple_switch --log-file ss-log --log-flush -i 0@veth2 -i 1@veth4 -i 2@veth6  $TARGET_JSON

simple_switch_CLI < commands.txt 

