/* EVMC: Ethereum Client-VM Connector API.
 * Copyright 2018 Pawel Bylica.
 * Licensed under the MIT License. See the LICENSE file.
 */

#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>

/**
 * Creates EVMC Example VM.
 */
EVMC_EXPORT struct evmc_instance* evmc_create_examplevm(void);
