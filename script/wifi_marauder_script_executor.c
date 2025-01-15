#include "../wifi_marauder_app_i.h"
#include "wifi_marauder_script_executor.h"

void _wifi_marauder_script_delay(WifiMarauderScriptWorker* worker, uint32_t delay_secs) {
    for(uint32_t i = 0; i < delay_secs && worker->is_running; i++) furi_delay_ms(1000);
}

void _send_stop(WifiMarauderScriptWorker* worker) {
    const char stop_command[] = "stopscan\n";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(stop_command), strlen(stop_command));
}

void _send_line_break(WifiMarauderScriptWorker* worker) {
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)("\n"), 1);
}

void _send_channel_select(WifiMarauderScriptWorker* worker, int channel) {
    char command[30];
    _send_line_break(worker);
    snprintf(command, sizeof(command), "channel -s %d\n", channel);
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(command), strlen(command));
}

void _wifi_marauder_script_execute_scan(
    WifiMarauderScriptStageScan* stage,
    WifiMarauderScriptWorker* worker) {
    char command[15];
    // Set channel
    if(stage->channel > 0) {
        _send_channel_select(worker, stage->channel);
    }
    // Start scan
    if(stage->type == WifiMarauderScriptScanTypeAp) {
        snprintf(command, sizeof(command), "scanap\n");
    } else {
        snprintf(command, sizeof(command), "scansta\n");
    }
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(command), strlen(command));
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_select(
    WifiMarauderScriptStageSelect* stage,
    WifiMarauderScriptWorker* worker) {
    const char* select_type = NULL;
    switch(stage->type) {
    case WifiMarauderScriptSelectTypeAp:
        select_type = "-a";
        break;
    case WifiMarauderScriptSelectTypeStation:
        select_type = "-c";
        break;
    case WifiMarauderScriptSelectTypeSsid:
        select_type = "-s";
        break;
    default:
        return; // invalid stage
    }

    char command[256];
    size_t command_length = 0;

    if(stage->indexes != NULL && stage->index_count > 0) {
        command_length = snprintf(command, sizeof(command), "select %s ", select_type);

        for(int i = 0; i < stage->index_count; i++) {
            int index = stage->indexes[i];
            command_length += snprintf(
                command + command_length, sizeof(command) - command_length, "%d, ", index);
        }

        // Remove the trailing comma and space
        command_length -= 2;
        command[command_length] = '\n';
        command_length++;
    } else if(stage->filter == NULL || strcmp(stage->filter, "all") == 0) {
        command_length = snprintf(command, sizeof(command), "select %s all\n", select_type);
    } else {
        command_length = snprintf(
            command, sizeof(command), "select %s -f \"%s\"\n", select_type, stage->filter);
    }

    wifi_marauder_uart_tx(worker->uart, (uint8_t*)command, command_length);
}

void _wifi_marauder_script_execute_deauth(
    WifiMarauderScriptStageDeauth* stage,
    WifiMarauderScriptWorker* worker) {
    const char attack_command[] = "attack -t deauth\n";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(attack_command), strlen(attack_command));
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_probe(
    WifiMarauderScriptStageProbe* stage,
    WifiMarauderScriptWorker* worker) {
    const char attack_command[] = "attack -t probe\n";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(attack_command), strlen(attack_command));
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_sniff_raw(
    WifiMarauderScriptStageSniffRaw* stage,
    WifiMarauderScriptWorker* worker) {
    const char sniff_command[] = "sniffraw";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)sniff_command, strlen(sniff_command));
    if(((WifiMarauderScript*)worker->context)->save_pcap != WifiMarauderScriptBooleanFalse) {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(" -serial\n"), strlen(" -serial\n"));
    } else {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)("\n"), 1);
    }
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_sniff_beacon(
    WifiMarauderScriptStageSniffBeacon* stage,
    WifiMarauderScriptWorker* worker) {
    const char sniff_command[] = "sniffbeacon";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)sniff_command, strlen(sniff_command));
    if(((WifiMarauderScript*)worker->context)->save_pcap != WifiMarauderScriptBooleanFalse) {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(" -serial\n"), strlen(" -serial\n"));
    } else {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)("\n"), 1);
    }
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_sniff_deauth(
    WifiMarauderScriptStageSniffDeauth* stage,
    WifiMarauderScriptWorker* worker) {
    const char sniff_command[] = "sniffdeauth";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)sniff_command, strlen(sniff_command));
    if(((WifiMarauderScript*)worker->context)->save_pcap != WifiMarauderScriptBooleanFalse) {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(" -serial\n"), strlen(" -serial\n"));
    } else {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)("\n"), 1);
    }
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_sniff_esp(
    WifiMarauderScriptStageSniffEsp* stage,
    WifiMarauderScriptWorker* worker) {
    const char sniff_command[] = "sniffesp";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)sniff_command, strlen(sniff_command));
    if(((WifiMarauderScript*)worker->context)->save_pcap != WifiMarauderScriptBooleanFalse) {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(" -serial\n"), strlen(" -serial\n"));
    } else {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)("\n"), 1);
    }
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_sniff_pmkid(
    WifiMarauderScriptStageSniffPmkid* stage,
    WifiMarauderScriptWorker* worker) {
    // If channel hopping is enabled, loop through channels 1-11
    if(stage->hop_channels) {
        for(int i = 1; i <= 11; i++) {
            char attack_command[50] = "sniffpmkid";
            int len = strlen(attack_command);

            len += snprintf(attack_command + len, sizeof(attack_command) - len, " -c %d", i);
            if(stage->force_deauth) {
                len += snprintf(attack_command + len, sizeof(attack_command) - len, " -d");
            }

            if(((WifiMarauderScript*)worker->context)->save_pcap !=
               WifiMarauderScriptBooleanFalse) {
                len += snprintf(attack_command + len, sizeof(attack_command) - len, " -serial\n");
            } else {
                len += snprintf(attack_command + len, sizeof(attack_command) - len, "\n");
            }
            wifi_marauder_uart_tx(worker->uart, (uint8_t*)attack_command, len);
            _wifi_marauder_script_delay(worker, stage->timeout);
            _send_stop(worker);
        }
    } else {
        char attack_command[50] = "sniffpmkid";
        int len = strlen(attack_command);

        if(stage->channel > 0) {
            len += snprintf(
                attack_command + len, sizeof(attack_command) - len, " -c %d", stage->channel);
        }

        if(stage->force_deauth) {
            len += snprintf(attack_command + len, sizeof(attack_command) - len, " -d");
        }
        if(((WifiMarauderScript*)worker->context)->save_pcap != WifiMarauderScriptBooleanFalse) {
            len += snprintf(attack_command + len, sizeof(attack_command) - len, " -serial\n");
        } else {
            len += snprintf(attack_command + len, sizeof(attack_command) - len, "\n");
        }
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)attack_command, len);
        _wifi_marauder_script_delay(worker, stage->timeout);
        _send_stop(worker);
    }
}

void _wifi_marauder_script_execute_sniff_pwn(
    WifiMarauderScriptStageSniffPwn* stage,
    WifiMarauderScriptWorker* worker) {
    const char sniff_command[] = "sniffpwn";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)sniff_command, strlen(sniff_command));
    if(((WifiMarauderScript*)worker->context)->save_pcap != WifiMarauderScriptBooleanFalse) {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(" -serial\n"), strlen(" -serial\n"));
    } else {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)("\n"), 1);
    }
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_beacon_list(
    WifiMarauderScriptStageBeaconList* stage,
    WifiMarauderScriptWorker* worker) {
    const char clearlist_command[] = "clearlist -s\n";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(clearlist_command), strlen(clearlist_command));

    char command[100];
    char* ssid;

    for(int i = 0; i < stage->ssid_count; i++) {
        ssid = stage->ssids[i];
        snprintf(command, sizeof(command), "ssid -a -n \"%s\"", ssid);
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(command), strlen(command));
        _send_line_break(worker);
    }
    if(stage->random_ssids > 0) {
        char add_random_command[50];
        snprintf(
            add_random_command,
            sizeof(add_random_command),
            "ssid -a -r -g %d\n",
            stage->random_ssids);
        wifi_marauder_uart_tx(
            worker->uart, (uint8_t*)add_random_command, strlen(add_random_command));
    }
    const char attack_command[] = "attack -t beacon -l\n";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(attack_command), strlen(attack_command));
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_beacon_ap(
    WifiMarauderScriptStageBeaconAp* stage,
    WifiMarauderScriptWorker* worker) {
    const char command[] = "attack -t beacon -a\n";
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)command, strlen(command));
    _wifi_marauder_script_delay(worker, stage->timeout);
    _send_stop(worker);
}

void _wifi_marauder_script_execute_exec(
    WifiMarauderScriptStageExec* stage,
    WifiMarauderScriptWorker* worker) {
    if(stage->command != NULL) {
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)stage->command, strlen(stage->command));
        _send_line_break(worker);
    }
}

void _wifi_marauder_script_execute_delay(
    WifiMarauderScriptStageDelay* stage,
    WifiMarauderScriptWorker* worker) {
    _wifi_marauder_script_delay(worker, stage->timeout);
}

char* _generate_omnom_ssid(WifiMarauderScriptWorker* worker) {
    static char ssid[33]; // Max SSID length is 32 chars + null terminator
    static uint32_t counter = 0;
    counter++;
    
    // Clear the SSID buffer
    memset(ssid, 0, sizeof(ssid));
    
    // Base patterns for variation
    const char* variants[] = {
        "om", "0m", "Om", "oM", "0M", "OM",
        "nom", "n0m", "Nom", "N0m", "NoM", "N0M"
    };
    
    // Start with a random base pattern
    uint8_t start_variant = counter % 6;
    strncpy(ssid, variants[start_variant], sizeof(ssid) - 1);
    
    // Calculate how many segments we can add (each segment is 3 chars)
    // Leave room for potential separator
    int max_segments = (31 - strlen(ssid)) / 3;
    
    // Add segments based on counter value
    int num_segments = (counter / 6) % max_segments + 1;
    
    for(int i = 0; i < num_segments; i++) {
        // Choose separator based on pattern
        char separator = (i % 2 == 0) ? '-' : '.';
        if(strlen(ssid) < 31) {
            strncat(ssid, &separator, 1);
        }
        
        // Select next variant pattern
        uint8_t variant_idx = ((counter + i) % 6) + 6; // Use the "nom" variants
        const char* next_variant = variants[variant_idx];
        
        // Add the variant if we have space
        if(strlen(ssid) + strlen(next_variant) <= 31) {
            strncat(ssid, next_variant, sizeof(ssid) - strlen(ssid) - 1);
        }
        
        // Additional variation: randomly capitalize one character if space permits
        if(strlen(ssid) < 31 && (counter + i) % 3 == 0) {
            int pos = strlen(ssid) - 1;
            if(ssid[pos] >= 'a' && ssid[pos] <= 'z') {
                ssid[pos] = toupper((unsigned char)ssid[pos]);
            }
        }
    }
    
    // Ensure the SSID ends with a number if possible
    if(strlen(ssid) < 31) {
        char num = '0' + (counter % 10);
        strncat(ssid, &num, 1);
    }
    
    return ssid;
}

void _wifi_marauder_script_execute_wep_handshake(
    WifiMarauderScriptStageWepHandshake* stage,
    WifiMarauderScriptWorker* worker) {
    
    // Initial setup - ensure we're on a good channel for WEP
    char channel_cmd[] = "channel -s 6\n"; // Channel 6 is often less crowded
    wifi_marauder_uart_tx(worker->uart, (uint8_t*)(channel_cmd), strlen(channel_cmd));
    furi_delay_ms(500);

    // We'll simulate 5 handshakes with different SSIDs
    for(int i = 0; i < 5 && worker->is_running; i++) {
        char* ssid = _generate_omnom_ssid(worker);
        
        // Configure attack parameters
        char config_cmd[100];
        // Use WEP 64-bit (40-bit key + 24-bit IV)
        snprintf(config_cmd, sizeof(config_cmd), 
                "attack -t wep -s \"%s\" -c 6 --enc wep64 --auth open\n", 
                ssid);
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(config_cmd), strlen(config_cmd));
        
        // Allow time for attack configuration
        furi_delay_ms(800);
        
        // Start handshake simulation
        const char start_cmd[] = "start\n";
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)(start_cmd), strlen(start_cmd));
        
        // Wait for full handshake sequence (authentication + association)
        // WEP handshakes typically need a bit more time than WPA
        _wifi_marauder_script_delay(worker, 3);
        
        // Stop the current simulation
        _send_stop(worker);
        
        // Display status on Flipper's screen (if available)
        if(worker->app->text_box) {
            FuriString* str = furi_string_alloc();
            furi_string_printf(str, "Generated WEP Handshake\nSSID: %s\n", ssid);
            text_box_set_text(worker->app->text_box, furi_string_get_cstr(str));
            furi_string_free(str);
        }
        
        // Longer delay between handshakes to allow pwnagotchi processing
        _wifi_marauder_script_delay(worker, 2);
    }
    
    // Final delay to ensure last handshake is captured
    _wifi_marauder_script_delay(worker, 1);
}

void wifi_marauder_script_execute_start(void* context) {
    furi_assert(context);
    WifiMarauderScriptWorker* worker = context;
    WifiMarauderScript* script = worker->script;
    char command[100];

    // Enables or disables the LED according to script settings
    if(script->enable_led != WifiMarauderScriptBooleanUndefined) {
        snprintf(
            command,
            sizeof(command),
            "settings -s EnableLED %s",
            script->enable_led ? "enable" : "disable");
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)command, strlen(command));
        _send_line_break(worker);
    }

    // Enables or disables PCAP saving according to script settings
    if(script->save_pcap != WifiMarauderScriptBooleanUndefined) {
        snprintf(
            command,
            sizeof(command),
            "settings -s SavePCAP %s",
            script->save_pcap ? "enable" : "disable");
        wifi_marauder_uart_tx(worker->uart, (uint8_t*)command, strlen(command));
        _send_line_break(worker);
    }
}

void wifi_marauder_script_execute_stage(WifiMarauderScriptStage* stage, void* context) {
    furi_assert(context);
    WifiMarauderScriptWorker* worker = context;
    void* stage_data = stage->stage;

    switch(stage->type) {
    case WifiMarauderScriptStageTypeScan:
        _wifi_marauder_script_execute_scan((WifiMarauderScriptStageScan*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSelect:
        _wifi_marauder_script_execute_select((WifiMarauderScriptStageSelect*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeDeauth:
        _wifi_marauder_script_execute_deauth((WifiMarauderScriptStageDeauth*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeProbe:
        _wifi_marauder_script_execute_probe((WifiMarauderScriptStageProbe*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSniffRaw:
        _wifi_marauder_script_execute_sniff_raw(
            (WifiMarauderScriptStageSniffRaw*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSniffBeacon:
        _wifi_marauder_script_execute_sniff_beacon(
            (WifiMarauderScriptStageSniffBeacon*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSniffDeauth:
        _wifi_marauder_script_execute_sniff_deauth(
            (WifiMarauderScriptStageSniffDeauth*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSniffEsp:
        _wifi_marauder_script_execute_sniff_esp(
            (WifiMarauderScriptStageSniffEsp*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSniffPmkid:
        _wifi_marauder_script_execute_sniff_pmkid(
            (WifiMarauderScriptStageSniffPmkid*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeSniffPwn:
        _wifi_marauder_script_execute_sniff_pwn(
            (WifiMarauderScriptStageSniffPwn*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeBeaconList:
        _wifi_marauder_script_execute_beacon_list(
            (WifiMarauderScriptStageBeaconList*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeBeaconAp:
        _wifi_marauder_script_execute_beacon_ap(
            (WifiMarauderScriptStageBeaconAp*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeExec:
        _wifi_marauder_script_execute_exec((WifiMarauderScriptStageExec*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeDelay:
        _wifi_marauder_script_execute_delay((WifiMarauderScriptStageDelay*)stage_data, worker);
        break;
    case WifiMarauderScriptStageTypeWepHandshake:
        _wifi_marauder_script_execute_wep_handshake(
            (WifiMarauderScriptStageWepHandshake*)stage_data, worker);
        break;
    }
}