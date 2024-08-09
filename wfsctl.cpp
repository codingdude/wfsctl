#if _MSC_VER
#pragma warning(disable : 4996)
#endif

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#include "getopt.h"
#include "parse-datetime.h"

#define WFS_MAGIC        0x342E30534657
#define WFS_SIGNATURE    0x4D58

#define WFS_OK           0x0
#define WFS_FAIL         0xFF

#define WFS_INVALID_VAL  -1

#define WFS_HEADER       0x0
#define WFS_SUPERB       0x18

#define WFS_DESC_SIZE    0x20

typedef enum wfs_fragment_attr_e : uint16_t
{
    FATTR_RESERVED     = 0xFE00, /* pending I/O operation */
    FATTR_MAIN1        = 0x0300, /* the fragment is in the beginning of the sequence */
    FATTR_MAIN2        = 0x0200, /* the fragment is in the beginning of the sequence */
    FATTR_SECONDARY    = 0x0100  /* the fragment is not in the beginning of the sequence */
} wfs_fragment_attr_t;

typedef struct wfs_superblock_s
{
    std::time_t        last_appears_ts;    /* timestamp of the last period of videos that appears in the “data area" */
    std::time_t        last_recorded_ts;   /* timestamp of the last video recorded by the equipment */

    uint32_t           last_recorded_desc; /* position, within the “index area”, of the descriptor of the
                                            * last fragment recorded by the equipment */

    uint32_t           first_valid_desc;   /* position, within the “index area”, of the descriptor of the
                                            * first valid fragment after the descriptors of the fragments that will be overwritten */

    uint32_t           total_frag_cnt;     /* total amount of fragments */

    std::time_t        first_valid_ts;     /* timestamp of the first valid fragment after the descriptors
                                            * of the fragments that will be overwritten */

    std::time_t        first_appears_ts;   /* start timestamp of the first period of “data area” videos */
    uint32_t           logical_block_size; /* size of a disk block */
    uint32_t           frag_size;          /* size of a video fragment, in number of disk blocks */
    uint32_t           frags_reserved;     /* number of reserved fragments */
    uint32_t           index_table_addr;   /* starting position of the “indices area” */
    uint32_t           data_addr;          /* start position of the “data area” */

} wfs_superblock_t;

typedef struct wfs_descriptor_s
{
    uint16_t    attr;  /* attribute */
    uint16_t    frag;  /* the fragments count or number of the current fragment (depends on attribute) */
    uint32_t    prev;  /* the number of the previous descriptor */
    uint32_t    next;  /* the number of the next descriptor */
    std::time_t start; /* fragment start date/time */
    std::time_t stop;  /* fragment end date/time */
    uint32_t    size;  /* number of LBA's of the last fragment (for 1st and last fragments only) */
    uint32_t    main;  /* the number of the main descriptor */
    uint16_t    chan ; /* channel? */
    uint16_t    cam;   /* camera identifier */
} wfs_descriptor_t;

typedef enum wfs_optarg_e
{
    WFS_DEV_ARG   = (1 << 0),
    WFS_START_ARG = (1 << 1),
    WFS_STOP_ARG  = (1 << 2),
    WFS_CAM_ARG   = (1 << 3),
    WFS_EXT_ARG   = (1 << 4),
    WFS_LST_ARG   = (1 << 5)
} wfs_optarg_t;

typedef struct wfs_options_s
{
    uint32_t opts;
    const char* dev;
    uint32_t cam;
    uint32_t start;
    uint32_t stop;
} wfs_options_t;

typedef int (*wfs_enum_callback)(const wfs_superblock_t* superb, wfs_descriptor_t* desc, uint32_t index, uint8_t* indextab);

static HANDLE device;

static inline bool wfs_main_descriptor(uint16_t attr);
static inline uint16_t wfs_camera_hash(uint8_t camera_id);
static inline uint64_t wfs_lba_offset(uint32_t lba, uint32_t lbs);
static inline uint8_t* wfs_skip(uint8_t* ptr, int nbytes);
static inline uint16_t wfs_parse_u16(uint8_t*& ptr);
static inline uint32_t wfs_parse_u32(uint8_t*& ptr);
static std::time_t wfs_parse_ts(uint8_t*& ptr);
static int wfs_parse_superblock(wfs_superblock_t& superb);
static int wfs_parse_desc(uint8_t* ptr, wfs_descriptor_t& desc);
static int wfs_device_open(const char* devid);
static void wfs_device_close(void);
static uint8_t* wfs_get_memory_region(int lba, int lbs, int count);
static void wfs_free_memory_region(uint8_t* region);
static int wfs_validate_signature(const wfs_superblock_t* superb);
static int wfs_enumerate_index_table(const wfs_superblock_t* superb,
    std::time_t start_time, std::time_t end_time,
    uint16_t camera_id, wfs_enum_callback callback);
static int wfs_print_descriptor(const wfs_superblock_t* superb,
    wfs_descriptor_t* desc, uint32_t index, uint8_t* indextab);
static int wfs_index_table_list(const wfs_superblock_t* superb,
    std::time_t start_time, std::time_t end_time, uint16_t camera_id);

static inline bool
wfs_main_descriptor(uint16_t attr)
{
    return attr == FATTR_MAIN1 ||
           attr == FATTR_MAIN2;
}

static inline uint16_t
wfs_camera_hash(uint8_t camera_id)
{
    return (2 + (camera_id - 1) * 4) << 8;
}

static inline uint64_t
wfs_lba_offset(uint32_t lba, uint32_t lbs)
{
    return uint64_t(lba) * lbs;
}

static inline uint8_t*
wfs_skip(uint8_t* ptr, int nbytes)
{
    return ptr + nbytes;
}

static inline uint16_t
wfs_parse_u16(uint8_t*& ptr)
{
    const uint16_t val = *reinterpret_cast<uint16_t*>(ptr);
    ptr += sizeof(uint16_t);
    return val;
}

static inline uint32_t
wfs_parse_u32(uint8_t*& ptr)
{
    const uint32_t val = *reinterpret_cast<uint32_t*>(ptr);
    ptr += sizeof(uint32_t);
    return val;
}

static std::time_t
wfs_parse_ts(uint8_t*& ptr)
{
    const uint32_t val = *reinterpret_cast<uint32_t*>(ptr);
    ptr += sizeof(uint32_t);

    std::tm gmt{};

    gmt.tm_year = ((val & 0xFC000000) >> 26) + 100;
    gmt.tm_mon = ((val & 0x03C00000) >> 22) - 1;
    gmt.tm_mday = ((val & 0x003E0000) >> 17);
    gmt.tm_hour = ((val & 0x0001F000) >> 12);
    gmt.tm_min = ((val & 0x00000FC0) >> 6);
    gmt.tm_sec = (val & 0x0000001F);

    return std::mktime(&gmt);
}

static int
wfs_parse_superblock(wfs_superblock_t& superb)
{
    uint8_t *rawdata, *region;
    
    /* superblock location always starts at 0x3000 */
    if (region = wfs_get_memory_region(WFS_SUPERB, 0x200, 1))
    {
        rawdata = wfs_skip(region, 16);
        superb.last_appears_ts = wfs_parse_ts(rawdata);
        superb.last_recorded_ts = wfs_parse_ts(rawdata);
        superb.last_recorded_desc = wfs_parse_u32(rawdata);
        superb.first_valid_desc = wfs_parse_u32(rawdata);
        superb.total_frag_cnt = wfs_parse_u32(rawdata);
        superb.first_valid_ts = wfs_parse_ts(rawdata);
        superb.first_appears_ts = wfs_parse_ts(rawdata);
        superb.logical_block_size = wfs_parse_u32(rawdata);
        superb.frag_size = wfs_parse_u32(rawdata);
        rawdata = wfs_skip(rawdata, 4);
        superb.frags_reserved = wfs_parse_u32(rawdata);
        rawdata = wfs_skip(rawdata, 8);
        superb.index_table_addr = wfs_parse_u32(rawdata);
        superb.data_addr = wfs_parse_u32(rawdata);

        wfs_free_memory_region(region);

        return WFS_OK;
    }

    return WFS_FAIL;
}

static int
wfs_parse_desc(uint8_t* ptr, wfs_descriptor_t& desc)
{
    if (ptr == nullptr)
    {
        return WFS_FAIL;
    }

    desc.attr = wfs_parse_u16(ptr);
    desc.frag = wfs_parse_u16(ptr);
    desc.prev = wfs_parse_u32(ptr);
    desc.next = wfs_parse_u32(ptr);
    desc.start = wfs_parse_ts(ptr);
    desc.stop = wfs_parse_ts(ptr);
    ptr = wfs_skip(ptr, 2);
    desc.size = wfs_parse_u16(ptr);
    desc.main = wfs_parse_u32(ptr);
    desc.chan = wfs_parse_u16(ptr);
    desc.cam = wfs_parse_u16(ptr);

    return WFS_OK;
}

static const char*
wfs_make_filename(std::time_t time)
{
    std::tm* gmt;
    static char buf[1024];

    std::memset(buf, 0, 1024);
    if (gmt = std::gmtime(&time))
    {
        std::snprintf(buf, 1024, "%02d-%02d-%04d-%02d-%02d-%02d.h265",
            gmt->tm_mday, gmt->tm_mon + 1, gmt->tm_year + 1900,
            gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
    }

    return buf;
}

static int
wfs_device_open(const char* devid)
{
    HANDLE hdevice;

    if (devid == NULL || *devid == NULL)
    {
        return WFS_FAIL;
    }

    if (device != NULL)
    {
        /* already opened */
        return WFS_OK;
    }
    
    hdevice = CreateFileA(
        devid,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hdevice == INVALID_HANDLE_VALUE)
    {
        return WFS_FAIL;
    }

    device = hdevice;

    return WFS_OK;
}

static void
wfs_device_close(void)
{
    if (device != NULL)
    {
        CloseHandle(device);
    }
}

static uint8_t*
wfs_get_memory_region(int lba, int lbs, int count)
{
    LARGE_INTEGER offset;
    LONG low, high;
    uint8_t* region;
    DWORD result;
    SIZE_T size;
    BOOL status;

    if (count <= 0)
    {
        return nullptr;
    }

    offset.QuadPart = wfs_lba_offset(lba, lbs);
    size = (SIZE_T) wfs_lba_offset(count, lbs);
    low = offset.LowPart;
    high = offset.HighPart;

    result = SetFilePointer(
        device,
        low, &high,
        FILE_BEGIN);

    if (result == INVALID_SET_FILE_POINTER)
    {
        return nullptr;
    }

    region = static_cast<uint8_t*>(
        VirtualAlloc(
            NULL,
            size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE));

    if (region == nullptr)
    {
        return nullptr;
    }

    status = ReadFile(
        device,
        region,
        size,
        &result,
        NULL);

    if (status != TRUE || result != size)
    {
        VirtualFree(region, 0, MEM_RELEASE);
        return nullptr;
    }

    status = VirtualProtect(
        region,
        size,
        PAGE_READONLY,
        &result);

    if (status != TRUE)
    {
        VirtualFree(region, 0, MEM_RELEASE);
        return nullptr;
    }

    return region;
}

static void
wfs_free_memory_region(uint8_t* region)
{
    if (region != nullptr)
    {
        VirtualFree(region, 0, MEM_RELEASE);
    }
}

static int
wfs_validate_signature(const wfs_superblock_t* superb)
{
    const uint8_t identifier[] = { 0x57,0x46,0x53,0x30,0x2E,0x34 };
    const uint8_t signature[] = { 0x58,0x4D };

    uint8_t* rawdata = nullptr;
    uint8_t* region = nullptr;
    int status = WFS_FAIL;

    if (region = wfs_get_memory_region(WFS_HEADER, superb->logical_block_size, 1))
    {
        rawdata = region;
        if (std::memcmp(rawdata, identifier, sizeof(identifier)) != 0)
        {
            goto exit;
        }

        rawdata = wfs_skip(rawdata, 510);
        if (std::memcmp(rawdata, signature, sizeof(signature)) != 0)
        {
            goto exit;
        }

        status = WFS_OK;
    }

exit:;
    wfs_free_memory_region(region);
    return status;
}

static int
wfs_enumerate_index_table(
    const wfs_superblock_t* superb,
    std::time_t start_time,
    std::time_t end_time,
    uint16_t camera_id,
    wfs_enum_callback callback)
{
    const int lba_cnt = (superb->total_frag_cnt * WFS_DESC_SIZE +
                         superb->logical_block_size - 1) / superb->logical_block_size;

    int lba, status;
    uint8_t *region, *ptr;
    wfs_descriptor_t desc;

    if (wfs_validate_signature(superb) != WFS_OK)
    {
        return WFS_FAIL;
    }

    status = WFS_FAIL;
    lba = superb->index_table_addr;
    if (region = wfs_get_memory_region(lba, superb->logical_block_size, lba_cnt))
    {
        status = WFS_OK;
        lba += lba_cnt; ptr = region;
        for (uint32_t desc_idx = 0; desc_idx < superb->total_frag_cnt; ++desc_idx)
        {
            if (wfs_parse_desc(ptr, desc) == WFS_FAIL)
            {
                status = WFS_FAIL;
                break;
            }

            ptr += WFS_DESC_SIZE;
            if (desc.chan != 1)
            {
                continue;
            }

            if (wfs_main_descriptor(desc.attr) &&
                start_time <= desc.start &&
                end_time >= desc.stop &&
                camera_id == desc.cam)
            {
                if (callback(superb , &desc, desc_idx, region))
                {
                    status = WFS_FAIL;
                    break;
                }
            }
        }

        wfs_free_memory_region(region);
    }

    return status;
}

static int
wfs_print_descriptor(
    const wfs_superblock_t* superb,
    wfs_descriptor_t* desc,
    uint32_t index,
    uint8_t* indextab)
{
    std::tm start, stop, *ptm;

    ptm = std::gmtime(&desc->start);
    if (ptm == nullptr)
    {
        return WFS_FAIL;
    }

    start = *ptm;

    ptm = std::gmtime(&desc->stop);
    if (ptm == nullptr)
    {
        return WFS_FAIL;
    }

    stop = *ptm;

    std::printf(
        "%02d-%02d-%d-%02d:%02d:%02d/%02d-%02d-%d-%02d:%02d:%02d\n",
        start.tm_mday, start.tm_mon + 1, start.tm_year + 1900,
        start.tm_hour, start.tm_min, start.tm_sec,
        stop.tm_mday, stop.tm_mon + 1, stop.tm_year + 1900,
        stop.tm_hour, stop.tm_min, stop.tm_sec);

    return WFS_OK;
}

static int
wfs_write_file(
    const wfs_superblock_t* superb,
    wfs_descriptor_t* desc,
    uint32_t index,
    uint8_t* indextab)
{
    uint32_t frag_cnt, lba_cnt;
    uint8_t* data;
    int status;
    const char* filename;
    HANDLE hfile;
    DWORD size, nbytes;

    filename = wfs_make_filename(desc->start);
    if (filename == 0 || filename[0] == 0)
    {
        return WFS_FAIL;
    }

    hfile = CreateFileA(
        filename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hfile == INVALID_HANDLE_VALUE)
    {
        return WFS_FAIL;
    }

    status = WFS_OK;
    frag_cnt = desc->frag;
    for (uint32_t frag_idx = 0; frag_idx <= frag_cnt; ++frag_idx)
    {
        lba_cnt = index * superb->frag_size;

        if (frag_idx == frag_cnt && desc->size != 0)
        {
            data = wfs_get_memory_region(superb->data_addr + lba_cnt,
                superb->logical_block_size, desc->size);

            if (data == nullptr)
            {
                status = WFS_FAIL;
                break;
            }

            size = superb->logical_block_size * desc->size;
        }
        else
        {
            data = wfs_get_memory_region(superb->data_addr + lba_cnt,
                superb->logical_block_size, superb->frag_size);

            if (data == nullptr)
            {
                status = WFS_FAIL;
                break;
            }

            size = superb->logical_block_size * superb->frag_size;
        }

        if (WriteFile(hfile, data, size, &nbytes, NULL) != TRUE)
        {
            wfs_free_memory_region(data);
            status = WFS_FAIL;
            break;
        }

        wfs_free_memory_region(data);

        if (desc->next != uint32_t(-1) && desc->next != 0)
        {
            index = desc->next;
            if (wfs_parse_desc(indextab + index * WFS_DESC_SIZE, *desc) != WFS_OK)
            {
                wfs_free_memory_region(data);
                status = WFS_FAIL;
                break;
            }
        }
    }

    CloseHandle(hfile);

    return status;
}

static int wfs_index_table_list(
    const wfs_superblock_t* superb,
    std::time_t start_time,
    std::time_t end_time,
    uint16_t camera_id)
{
    return wfs_enumerate_index_table(
        superb,
        start_time,
        end_time,
        camera_id,
        wfs_print_descriptor);
}

static int wfs_write_files(
    const wfs_superblock_t* superb,
    std::time_t start_time,
    std::time_t end_time,
    uint16_t camera_id)
{
    return wfs_enumerate_index_table(
        superb,
        start_time,
        end_time,
        camera_id,
        wfs_write_file);
}

static std::time_t
wfs_parse_unix_time(const char* timestr)
{
    struct timespec t;

    if (!timestr || !timestr[0])
    {
        return 0;
    }

    if (!parse_datetime(&t, timestr, nullptr))
    {
        return 0;
    }

    return t.tv_sec;
}

static int
wfs_parse_options(int argc, char* argv[], wfs_options_t* out)
{
    int opt, idx;

    const struct option longopt[] =
    {
        { "device", required_argument, NULL, 1 },
        { "start", required_argument, NULL, 2 },
        { "stop", required_argument, NULL, 3 },
        { "camera", required_argument, NULL, 4 },
        { "extract", no_argument, NULL, 5 },
        { "list", no_argument, NULL, 6 },
        { NULL, 0, NULL, 0 }
    };

    std::memset(out, 0, sizeof(wfs_options_t));
    out->start = 0;
    out->stop = uint32_t(std::time(nullptr));

    while ((opt = getopt_long(argc, argv, "", longopt, &idx)) != -1)
    {
        switch (opt)
        {
        case 1:
            out->opts |= WFS_DEV_ARG;
            out->dev = optarg;
            break;
        case 2:
            out->opts |= WFS_START_ARG;
            out->start = wfs_parse_unix_time(optarg);
            if (out->start == 0)
            {
                return WFS_FAIL;
            }
            break;
        case 3:
            out->opts |= WFS_STOP_ARG;
            out->stop = wfs_parse_unix_time(optarg);
            if (out->stop == 0)
            {
                return WFS_FAIL;
            }
            break;
        case 4:
            out->opts |= WFS_CAM_ARG;
            out->cam = std::atoi(optarg);
            break;
        case 5:
            if (out->opts & WFS_LST_ARG)
            {
                return WFS_FAIL;
            }
            out->opts |= WFS_EXT_ARG;
            break;
        case 6:
            if (out->opts & WFS_EXT_ARG)
            {
                return WFS_FAIL;
            }
            out->opts |= WFS_LST_ARG;
            break;
        default:
            return WFS_FAIL;
        }
    }

    if (!(out->opts & WFS_EXT_ARG) &&
        !(out->opts & WFS_LST_ARG))
    {
        return WFS_FAIL;
    }

    if (!(out->opts & WFS_CAM_ARG) ||
        !(out->opts & WFS_DEV_ARG))
    {
        return WFS_FAIL;
    }

    return WFS_OK;
}

int
main(int argc, char* argv[])
{
    wfs_superblock_t superb;
    wfs_options_t opts;

    if (wfs_parse_options(argc, argv, &opts) != WFS_OK)
    {
        std::puts("HELP:\n"
            "--list                     : list video fragments\n"
            "--extract                  : extract video fragments\n"
            "--device=\"\\\\.\\F:\"          : source identifier\n"
            "--camera=\"1\"               : camera identifier\n"
            "--start=\"YYYY/MM/DD HH:MM\" : start date (optional)\n"
            "--stop=\"YYYY/MM/DD HH:MM\"  : stop date (optional)\n");

        return EXIT_SUCCESS;
    }

    if (wfs_device_open(opts.dev) != WFS_OK)
    {
        std::printf("can't open the device '%s'", opts.dev);
        return EXIT_FAILURE;
    }

    if (wfs_parse_superblock(superb) != WFS_OK)
    {
        std::puts("unable to read surerblock");
        wfs_device_close();
        return EXIT_FAILURE;
    }

    if (opts.opts & WFS_EXT_ARG)
    {
        if (wfs_write_files(&superb, opts.start, opts.stop, wfs_camera_hash(opts.cam)) != WFS_OK)
        {
            std::puts("unable to extract data");
            wfs_device_close();
            return EXIT_FAILURE;
        }
    }

    if (opts.opts & WFS_LST_ARG)
    {
        if (wfs_index_table_list(&superb, opts.start, opts.stop, wfs_camera_hash(opts.cam)) != WFS_OK)
        {
            std::puts("unable to read index table");
            wfs_device_close();
            return EXIT_FAILURE;
        }
    }

    wfs_device_close();

    return EXIT_SUCCESS;
}
