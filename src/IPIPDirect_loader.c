#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <inttypes.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>

#include "include/libbpf/src/bpf.h"
#include "include/libbpf/src/libbpf.h"
#include "include/common.h"

// TC CMD sizes.
#define CMD_MAX 2048
#define CMD_MAX_TC 256

// Initialize static variables.
static uint8_t cont = 1;
static int mac_map_fd;
static uint8_t gwMAC[ETH_ALEN];

// TC program file name.
const char TCFile[] = "/etc/IPIPDirect/IPIPDirect_filter.o";

// Maps.
const char *map_mac = BASEDIR_MAPS "/mac_map";

// Extern error number.
extern int errno;

// Signal function.
void signHdl(int tmp)
{
    // Set cont to 0 which will stop the while loop and the program.
    cont = 0;
}

// Get gateway MAC address.
void GetGatewayMAC()
{
    // Command to run.
    char cmd[] = "ip neigh | grep \"$(ip -4 route list 0/0 | cut -d' ' -f3) \" | cut -d' ' -f5 | tr '[a-f]' '[A-F]'";

    // Execute command.
    FILE *fp =  popen(cmd, "r");

    // Check if command is valid.
    if (fp != NULL)
    {
        // Initialize line char.
        char line[18];

        // Get output from command.
        if (fgets(line, sizeof(line), fp) != NULL)
        {
            // Parse output and put it into gwMAC.
            sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &gwMAC[0], &gwMAC[1], &gwMAC[2], &gwMAC[3], &gwMAC[4], &gwMAC[5]);
        }
        
        // Close command.
        pclose(fp);
    }
}

int open_map(const char *name)
{
    // Initialize FD.
    int fd;

    // Get map objective.
    fd = bpf_obj_get(name);

    // Check map FD.
    if (fd < 0)
    {
        fprintf(stderr, "Error getting map. Map name => %s\n", name);

        return fd;
    }

    // Return FD.
    return fd;
}

void bpf_close_and_exit(struct bpf_object *obj, int ret)
{
    bpf_object__close(obj);

    exit(ret);
}

void tc_egress_attach_bpf(int ifidx, const char *obj_path, const char *prog_name, struct bpf_object **obj, struct bpf_program **prog)
{
    int ret;

    *obj = bpf_object__open_file(obj_path, NULL);

    if (!(*obj))
    {
        fprintf(stderr, "Error opening BPF object (%s). Error => %d (%s).\n", obj_path, errno, strerror(errno));

        exit(errno);
    }
    
    if (bpf_object__load(*obj) != 0)
    {
        fprintf(stderr, "Error loading BPF object into kernel. Error => %d (%s).\n", errno, strerror(errno));

        bpf_close_and_exit(*obj, errno);
    }

    // Try unpinning maps first.
    bpf_object__unpin_maps(*obj, BASEDIR_MAPS);

    // Pin maps.
    bpf_object__pin_maps(*obj, BASEDIR_MAPS);

    *prog = bpf_object__find_program_by_name(*obj, prog_name);

    if (!(*prog))
    {
        fprintf(stderr, "Error loading BPF program with name 'tc_egress'. Error => %d (%s).\n", errno, strerror(errno));

        bpf_close_and_exit(*obj, errno);
    }

    int fd = bpf_program__fd(*prog);

    if (fd < 0)
    {
        fprintf(stderr, "BPF program FD is below 0! FD => %d.\n", fd);

        bpf_close_and_exit(*obj, 1);
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifidx,
        .attach_point = BPF_TC_EGRESS
    );

    if ((ret = bpf_tc_hook_destroy(&hook)) < 0)
    {
        fprintf(stderr, "Warning! Failed to destroy TC hook. Return code => %d.\n", ret);
    }

    if ((ret = bpf_tc_hook_create(&hook)) < 0)
    {
        if (ret != -17)
        {
            fprintf(stderr, "Failed to create TC hook. Return code => %d.\n", ret);

            bpf_close_and_exit(*obj, ret);
        }
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);

    if ((ret = bpf_tc_attach(&hook, &opts)) < 0)
    {
        fprintf(stderr, "Failed to attach TC program. Return code => %d.\n", ret);

        bpf_close_and_exit(*obj, errno);
    }
}

int tc_remove_egress_filter(int ifidx, struct bpf_object **obj)
{
    int ret;

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifidx,
        .attach_point = BPF_TC_EGRESS
    );

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = 0, .prog_id = 0);
    
    if ((ret = bpf_tc_hook_destroy(&hook)) < 0)
    {
        fprintf(stderr, "Failed to detach TC program. Return code => %d.\n", ret);
    }

    bpf_object__close(*obj);

    return ret;
}

int main(int argc, char *argv[])
{
    // Check argument count.
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <Interface>\n", argv[0]);

        exit(1);
    }

    // Initialize variables.
    int err, ifindex;

    // Get interface index.
    ifindex = if_nametoindex(argv[1]);

    // Check if interface is valid.
    if (ifindex <= 0)
    {
        fprintf(stderr, "Error loading interface (%s).\n", argv[1]);

        exit(1);
    }

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;

    // Attempt to attach to egress filter.
    tc_egress_attach_bpf(ifindex, TCFile, "tc_egress", &obj, &prog);

    // Get MAC map.
    mac_map_fd = open_map(map_mac);

    if (mac_map_fd < 0)
    {
        // Attempt to remove TC filter since map failed.
        err = tc_remove_egress_filter(ifindex, &obj);

        exit(err);
    }

    // Get gateway MAC address and store it in gwMAC.
    GetGatewayMAC();

    // Add gateway MAC address to the "mac_map" BPF map.
    uint64_t val;
    val = mac2int(gwMAC);

    uint32_t key2 = 0;

    bpf_map_update_elem(mac_map_fd, &key2, &val, BPF_ANY);

    // Signal calls so we can shutdown program.
    signal(SIGINT, signHdl);
    signal(SIGTERM, signHdl);
    signal(SIGKILL, signHdl);

    // Debug.
    fprintf(stdout, "Starting IPIP Direct TC egress program.\n");

    // Loop!
    while (cont)
    {
        // We sleep every second.
        sleep(1);
    }

    // Debug.
    fprintf(stdout, "Cleaning up...\n");

    // Remove TC egress filter.
    err = tc_remove_egress_filter(ifindex, &obj);

    exit(err);
}