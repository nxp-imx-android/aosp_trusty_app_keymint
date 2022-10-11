/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! This library implements the functionality used by the Keymint Trusty
//! application.
#![allow(unused)] //TODO: remove unused and fix any dependency issues.
#![no_std]

use kmr_ta;

mod keys;

pub use keys::TrustyKeys;

// TODO: maintain the bootloader status and update it as the bootloader informs
// Trusty when it is done.
pub struct TrustyBootLoaderStatus;
impl kmr_ta::device::BootloaderStatus for TrustyBootLoaderStatus {}

#[cfg(test)]
mod tests {
    test::init!();
}
