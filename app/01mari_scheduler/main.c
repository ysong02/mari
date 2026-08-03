/**
 * @file
 * @ingroup     drv_scheduler
 *
 * @brief       Example on how to use the TSCH scheduler
 *
 * @author Geovane Fedrecheski <geovane.fedrecheski@inria.fr>
 *
 * @copyright Inria, 2024
 */
#include <nrf.h>
#include <stdio.h>

#include "mr_timer_hf.h"
#include "mr_device.h"
#include "scheduler.h"
#include "mac.h"
#include "mari.h"

#define SLOT 1000 * 1000  // 1 s

// make some schedules available for testing
#include "test_schedules.c"
extern schedule_t schedule_minuscule, schedule_only_beacons_optimized_scan;

int main(void) {
    // initialize high frequency timer
    mr_timer_hf_init(MARI_TIMER_DEV);

    // initialize schedule
    schedule_t     schedule  = schedule_minuscule;
    mr_node_type_t node_type = MARI_NODE;

    mari_set_node_type(node_type);

    mr_scheduler_init(&schedule);

    printf("Device of type %c and id %llx is using schedule %d\n\n", node_type, mr_device_id(), schedule.id);

    // Tick the scheduler n_slotframes*n_cells times, assigning/deassigning the uplink cell partway through.
    size_t n_slotframes = 4;
    // uint64_t asn = (1ULL << 48) + 123456789; // use a large number to test scheduler tick duration
    uint64_t asn = 0;
    for (size_t j = 0; j < n_slotframes; j++) {
        for (size_t i = 0; i < schedule.n_cells; i++) {
            uint32_t       start_ts  = mr_timer_hf_now(MARI_TIMER_DEV);
            mr_slot_info_t slot_info = mr_scheduler_tick(asn++);
            printf("Scheduler tick took %d us\n", mr_timer_hf_now(MARI_TIMER_DEV) - start_ts);
            printf(">> Event %c:   %c, %d\n", slot_info.type, slot_info.radio_action, slot_info.channel);

            // sleep for the duration of the slot
            mr_timer_hf_delay_us(MARI_TIMER_DEV, SLOT);
        }
        puts(".");
        if (j == 0 && mr_scheduler_gateway_assign_next_available_uplink_cell(mr_device_id(), 0) < 0) {  // try to assign at the end of first slotframe
            printf("Failed to assign uplink cell\n");
            return 1;
        }
        // else if (j == n_slotframes-2 && !mr_scheduler_gateway_deassign_uplink_cell(mr_device_id())) { // try to deassign at the end of the second-to-last slotframe
        //     printf("Failed to deassign uplink cell\n");
        //     return 1;
        // }
    }
    puts("Finished.");

    while (1) {
        __WFE();
    }
}
