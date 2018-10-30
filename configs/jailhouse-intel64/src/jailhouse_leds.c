#include <arch/board/board.h>

void board_autoled_initialize(void){
    return;
}

void board_autoled_on(int led){
    if(led == LED_PANIC){
        /* Check jailhouse message */
        switch (comm_region->msg_to_cell) {
        case JAILHOUSE_MSG_SHUTDOWN_REQUEST:
          comm_region->cell_state = JAILHOUSE_CELL_SHUT_DOWN;
          for(;;){
            asm("cli");
            asm("hlt");
          }
          break;
        default:
          break;
        }
        return;
    }
}

void board_autoled_off(int state){
    return;
}
