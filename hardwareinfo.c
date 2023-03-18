#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cpuid.h>
#include <pci/pci.h>

#define DASH_LINE "-----------------------------------------------------\n"
#define SPACE_LINE "                                                     \n"

// 获取内存大小
static int get_total_ram() {
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    return (int)(pages * page_size / (1024 * 1024));
}

// 获取 CPU 微码
static char *get_cpu_microcode() {
    int fd = open("/dev/cpu/0/microcode", O_RDONLY);
    if (fd < 0) {
        return NULL;
    }
    char *microcode = mmap(NULL, 2097152, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (microcode == MAP_FAILED) {
        return NULL;
    }
    uint32_t header = *((uint32_t*)microcode);
    uint32_t rev = header >> 16;
    uint32_t date = header & 0xFFFF;
    uint32_t sig = *((uint32_t*)(microcode + 8));
    char *result = malloc(256);
    sprintf(result, "Revision: %08x\nDate: %08x\nSignature: %08x", rev, date, sig);
    munmap(microcode, 2097152);
    return result;
}

int main() {
    char *cpu_model = NULL;
    char *cpu_stepping = NULL;
    char *cpu_family = NULL;
    int total_ram = get_total_ram();
    char *cpu_microcode = get_cpu_microcode();
    struct pci_access *pacc;
    struct pci_dev *pdev;

    pacc = pci_alloc();     // 分配 PCI 管理器
    pci_init(pacc);         // 初始化 PCI 管理器
    pci_scan_bus(pacc);     // 扫描总线
    printf(DASH_LINE);
    printf("| %-50s |\n", "CPU Information");
    printf(DASH_LINE);

    FILE *cpuinfo = fopen("/proc/cpuinfo", "r");
    if (!cpuinfo) {
        return 1;
    }
    while (!feof(cpuinfo)) {
        char buf[1024] = {0};
        fgets(buf, sizeof(buf), cpuinfo);
        if (strstr(buf, "model name")) {
            cpu_model = strdup(strchr(buf, ':') + 2);
        } else if (strstr(buf, "stepping")) {
            cpu_stepping = strdup(strchr(buf, ':') + 2);
        } else if (strstr(buf, "cpu family")) {
            cpu_family = strdup(strchr(buf, ':') + 2);
        }
    }
    fclose(cpuinfo);

    printf("| %-20s | %-30s |\n", "Model", cpu_model ? cpu_model : "");
    printf("| %-20s | %-30s |\n", "CPU Family", cpu_family ? cpu_family : "");
    printf("| %-20s | %-30s |\n", "Stepping", cpu_stepping ? cpu_stepping : "");
    printf(DASH_LINE);
    printf("| %-50s |\n", "CPUID");
