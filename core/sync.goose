// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Concurrency primitives, singleflight call suppression, and SPSC lock-free queues.
namespace core;

import std;
import os;

import core.sync.singleflight;
import core.sync.spsc_ring;
