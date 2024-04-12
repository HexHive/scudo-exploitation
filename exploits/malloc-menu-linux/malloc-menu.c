#include <stdio.h>
#include <stdlib.h>

struct AllocBlock {
    void* address;
    size_t size;
};

struct AllocBlock blocks[20];
int num_blocks = 0;

void* get_addr() {
    printf("Enter 1 to get address from a block index, 2 to enter an address: ");
    int choice;
    scanf("%d", &choice);

    switch (choice) {
    case 1:
        printf("Enter the index of the block to get the address from: ");
        int index;
        scanf("%d", &index);

        printf("Enter the offset from the block start: ");
        int offset;
        scanf("%d", &offset);

        return blocks[index].address+offset;
    case 2:
        printf("Enter the address: ");
        void* addr;
        scanf("%llx", (long long unsigned*)&addr);

        return addr;
    default:
        printf("Invalid choice\n");
        return NULL;
    }
}

int main() {
    void* addr;
    size_t size;
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
        
    printf("Welcome to malloc menu program\n");
    int choice;
    do {
        printf("Choose an action:\n");
        printf("\t1 to allocate a block\n");
        printf("\t2 to free a block\n");
        printf("\t3 to write data to an address\n");
        printf("\t4 to dump the data at an address\n");
        printf("\t5 to list all blocks\n");
        printf("\t6 to quit\n");
        scanf("%d", &choice);
        switch (choice) {
        case 1:
            printf("Enter the size of the block to allocate: ");
            scanf("%zu", &size);
            
            blocks[num_blocks].address = malloc(size);
            blocks[num_blocks].size = size;
            
            printf("Allocated block with index %d at address 0x%llx\n", num_blocks, (long long unsigned)blocks[num_blocks].address);
            
            ++num_blocks;
            break;
        case 2:
            addr = get_addr();

            if (addr == NULL)
                break;
            
            free(addr);
            break;
        case 3:
            addr = get_addr();
            if (addr == NULL)
                break;
            
            printf("Enter the number of bytes you want to write: ");
            scanf("%zu", &size);

            char nl;
            fread(&nl, 1, 1, stdin);

            printf("Enter the data to write: ");
            for (void* it = addr; it != addr+size; ++it) {
                fread(it, 1, 1, stdin);
            }

            break;
        case 4:
            addr = get_addr();
            if (addr == NULL)
                break;

            printf("Enter the number of bytes you want to read: ");
            scanf("%zu", &size);

            for (size_t i = 0; i < size; i = i+8) {
                printf("0x%lx ", *((unsigned long*)(addr + i)));
            }
            printf("\n");
            break;
        case 5:
            printf("%d blocks:\n", num_blocks);
            for (int i = 0; i < num_blocks; ++i) {
                printf("\taddress: %llx size: %zu\n", (long long unsigned)blocks[i].address, blocks[i].size);
            }
            break;
        case 6:
            printf("Goodbye!\n");
            exit(0);
        default:
            printf("Invalid choice.\n");
            break;
        }
    } while (1);
}
