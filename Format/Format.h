#pragma once

#include <windows.h>
#include <winioctl.h>   // for DISK_GEOMETRY
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <winternl.h>
#include <Shlwapi.h>
#include <locale.h>


typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef signed char        int_least8_t;
typedef short              int_least16_t;
typedef int                int_least32_t;
typedef long long          int_least64_t;
typedef unsigned char      uint_least8_t;
typedef unsigned short     uint_least16_t;
typedef unsigned int       uint_least32_t;
typedef unsigned long long uint_least64_t;

typedef signed char        int_fast8_t;
typedef int                int_fast16_t;
typedef int                int_fast32_t;
typedef long long          int_fast64_t;
typedef unsigned char      uint_fast8_t;
typedef unsigned int       uint_fast16_t;
typedef unsigned int       uint_fast32_t;
typedef unsigned long long uint_fast64_t;

typedef long long          intmax_t;
typedef unsigned long long uintmax_t;



#define safe_free(p) do {free((void*)p); p = NULL;} while(0)
#define safe_mm_free(p) do {_mm_free((void*)p); p = NULL;} while(0)
#define safe_min(a, b) min((size_t)(a), (size_t)(b))
#define safe_strcp(dst, dst_max, src, count) do {memcpy(dst, src, safe_min(count, dst_max)); \
	((char*)dst)[safe_min(count, dst_max)-1] = 0;} while(0)
#define safe_strcpy(dst, dst_max, src) safe_strcp(dst, dst_max, src, safe_strlen(src)+1)
#define static_strcpy(dst, src) safe_strcpy(dst, sizeof(dst), src)
#define safe_strncat(dst, dst_max, src, count) strncat(dst, src, safe_min(count, dst_max - safe_strlen(dst) - 1))
#define safe_strcat(dst, dst_max, src) safe_strncat(dst, dst_max, src, safe_strlen(src)+1)
#define static_strcat(dst, src) safe_strcat(dst, sizeof(dst), src)
#define safe_strcmp(str1, str2) strcmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_strstr(str1, str2) strstr(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_stricmp(str1, str2) _stricmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2))
#define safe_strncmp(str1, str2, count) strncmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2), count)
#define safe_strnicmp(str1, str2, count) _strnicmp(((str1==NULL)?"<NULL>":str1), ((str2==NULL)?"<NULL>":str2), count)
#define safe_closehandle(h) do {if ((h != INVALID_HANDLE_VALUE) && (h != NULL)) {CloseHandle(h); h = INVALID_HANDLE_VALUE;}} while(0)
#define safe_release_dc(hDlg, hDC) do {if ((hDC != INVALID_HANDLE_VALUE) && (hDC != NULL)) {ReleaseDC(hDlg, hDC); hDC = NULL;}} while(0)
#define safe_sprintf(dst, count, ...) do {_snprintf(dst, count, __VA_ARGS__); (dst)[(count)-1] = 0; } while(0)
#define static_sprintf(dst, ...) safe_sprintf(dst, sizeof(dst), __VA_ARGS__)
#define safe_strlen(str) ((((char*)str)==NULL)?0:strlen(str))
#define safe_strdup _strdup

static __inline BOOL UnlockDrive(HANDLE hDrive) {
	DWORD size;
	return DeviceIoControl(hDrive, FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &size, NULL);
}
#define safe_unlockclose(h) do {if ((h != INVALID_HANDLE_VALUE) && (h != NULL)) {UnlockDrive(h); CloseHandle(h); h = INVALID_HANDLE_VALUE;}} while(0)


#define DRIVE_ACCESS_RETRIES        150			// How many times we should retry
#define DRIVE_ACCESS_TIMEOUT        15000		// How long we should retry drive access (in ms)
#define MBR_UEFI_MARKER             0x49464555	// 'U', 'E', 'F', 'I', as a 32 bit little endian longword
#define RUFUS_EXTRA_PARTITION_TYPE          0xea
#define MAX_DATA_LEN 32768
#define WRITE_RETRIES               4
#define MAX_SECTORS_TO_CLEAR        128			// nb sectors to zap when clearing the MBR/GPT (must be >34)
#define WRITE_TIMEOUT               5000		// How long we should wait between write retries

#define KB                   1024LL
#define MB                1048576LL
#define GB             1073741824LL
#define TB          1099511627776LL

#define FAC(f)                         (f<<16)
#define APPERR(err)                    (APPLICATION_ERROR_MASK|err)
#define ERROR_INCOMPATIBLE_FS          0x1201
#define ERROR_CANT_QUICK_FORMAT        0x1202
#define ERROR_INVALID_CLUSTER_SIZE     0x1203
#define ERROR_INVALID_VOLUME_SIZE      0x1204
#define ERROR_CANT_START_THREAD        0x1205
#define ERROR_BADBLOCKS_FAILURE        0x1206
#define ERROR_ISO_SCAN                 0x1207
#define ERROR_ISO_EXTRACT              0x1208
#define ERROR_CANT_REMOUNT_VOLUME      0x1209
#define ERROR_CANT_PATCH               0x120A
#define ERROR_CANT_ASSIGN_LETTER       0x120B
#define ERROR_CANT_MOUNT_VOLUME        0x120C

#define         MAX_LIBRARY_HANDLES 32
#define FILE_FLOPPY_DISKETTE                0x00000004

typedef struct _FILE_FS_DEVICE_INFORMATION {
	DEVICE_TYPE DeviceType;
	ULONG Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

HMODULE  OpenedLibrariesHandle[MAX_LIBRARY_HANDLES];
uint16_t OpenedLibrariesHandleSize;
#define         OPENED_LIBRARIES_VARS HMODULE OpenedLibrariesHandle[MAX_LIBRARY_HANDLES]; uint16_t OpenedLibrariesHandleSize = 0
#define         CLOSE_OPENED_LIBRARIES while(OpenedLibrariesHandleSize > 0) FreeLibrary(OpenedLibrariesHandle[--OpenedLibrariesHandleSize])
static __inline HMODULE GetLibraryHandle(const char* szLibraryName) {
	HMODULE h = NULL;
	if ((h = GetModuleHandleA(szLibraryName)) == NULL) {
		if (OpenedLibrariesHandleSize >= MAX_LIBRARY_HANDLES) {
			printf("Error: MAX_LIBRARY_HANDLES is too small\n");
		}
		else {
			h = LoadLibraryA(szLibraryName);
			if (h != NULL)
				OpenedLibrariesHandle[OpenedLibrariesHandleSize++] = h;
		}
	}
	return h;
}

#define PF_TYPE(api, ret, proc, args)		typedef ret (api *proc##_t)args
#define PF_DECL(proc)						static proc##_t pf##proc = NULL
#define PF_TYPE_DECL(api, ret, proc, args)	PF_TYPE(api, ret, proc, args); PF_DECL(proc)
#define PF_INIT(proc, name)					if (pf##proc == NULL) pf##proc = \
	(proc##_t) GetProcAddress(GetLibraryHandle(#name), #proc)


#define LEFT_TO_RIGHT_MARK          ""
#define RIGHT_TO_LEFT_MARK          ""
#define LEFT_TO_RIGHT_EMBEDDING     ""
#define RIGHT_TO_LEFT_EMBEDDING     ""
#define POP_DIRECTIONAL_FORMATTING  ""
#define LEFT_TO_RIGHT_OVERRIDE      ""
#define RIGHT_TO_LEFT_OVERRIDE      ""

enum target_type {
	TT_BIOS = 0,
	TT_UEFI,
	TT_MAX
};

/* File system indexes in our FS combobox */
enum fs_type {
	FS_UNKNOWN = -1,
	FS_FAT16 = 0,
	FS_FAT32,
	FS_NTFS,
	FS_UDF,
	FS_EXFAT,
	FS_REFS,
	FS_MAX
};

/* Current drive info */
typedef struct {
	LONGLONG DiskSize;
	DWORD DeviceNumber;
	DWORD SectorsPerTrack;
	DWORD SectorSize;
	DWORD FirstDataSector;
	MEDIA_TYPE MediaType;
	int PartitionStyle;
	int nPartitions;	// number of partitions we actually care about
	int FSType;
	char proposed_label[16];
	BOOL has_protective_mbr;
	BOOL has_mbr_uefi_marker;
	struct {
		ULONG Allowed;
		ULONG Default;
	} ClusterSize[FS_MAX];
} RUFUS_DRIVE_INFO;


/* We hijack the FILE structure for our own needs */
typedef struct {
	void *_handle;
	uint64_t _offset;
} FAKE_FD;




/* We need a redef of these MS structure */
typedef struct {
	DWORD DeviceType;
	ULONG DeviceNumber;
	ULONG PartitionNumber;
} STORAGE_DEVICE_NUMBER_REDEF;

typedef struct {
	DWORD NumberOfDiskExtents;
	// The one from MS uses ANYSIZE_ARRAY, which can lead to all kind of problems
	DISK_EXTENT Extents[8];
} VOLUME_DISK_EXTENTS_REDEF;

typedef enum _FSINFOCLASS {
	FileFsVolumeInformation = 1,
	FileFsLabelInformation,
	FileFsSizeInformation,
	FileFsDeviceInformation,
	FileFsAttributeInformation,
	FileFsControlInformation,
	FileFsFullSizeInformation,
	FileFsObjectIdInformation,
	FileFsDriverPathInformation,
	FileFsVolumeFlagsInformation,
	FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

enum boot_type {
	BT_MSDOS = 0,
	BT_FREEDOS,
	BT_IMAGE,
	BT_SYSLINUX_V4,		// Start of indexes that only display in advanced mode
	BT_SYSLINUX_V6,
	BT_REACTOS,
	BT_GRUB4DOS,
	BT_GRUB2,
	BT_UEFI_NTFS,
	BT_NON_BOOTABLE,
	BT_MAX
};

typedef struct _DRIVE_LAYOUT_INFORMATION_EX4 {
	DWORD PartitionStyle;
	DWORD PartitionCount;
	union {
		DRIVE_LAYOUT_INFORMATION_MBR Mbr;
		DRIVE_LAYOUT_INFORMATION_GPT Gpt;
	} Type;
	PARTITION_INFORMATION_EX PartitionEntry[4];
} DRIVE_LAYOUT_INFORMATION_EX4, *PDRIVE_LAYOUT_INFORMATION_EX4;

typedef NTSTATUS(__stdcall * NtQueryVolumeInformationFile_t)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FS_INFORMATION_CLASS);

/* Callback command types (some errorcode were filled from HPUSBFW V2.2.3 and their
designation from msdn.microsoft.com/en-us/library/windows/desktop/aa819439.aspx */
typedef enum {
	FCC_PROGRESS,
	FCC_DONE_WITH_STRUCTURE,
	FCC_UNKNOWN2,
	FCC_INCOMPATIBLE_FILE_SYSTEM,
	FCC_UNKNOWN4,
	FCC_UNKNOWN5,
	FCC_ACCESS_DENIED,
	FCC_MEDIA_WRITE_PROTECTED,
	FCC_VOLUME_IN_USE,
	FCC_CANT_QUICK_FORMAT,
	FCC_UNKNOWNA,
	FCC_DONE,
	FCC_BAD_LABEL,
	FCC_UNKNOWND,
	FCC_OUTPUT,
	FCC_STRUCTURE_PROGRESS,
	FCC_CLUSTER_SIZE_TOO_SMALL,
	FCC_CLUSTER_SIZE_TOO_BIG,
	FCC_VOLUME_TOO_SMALL,
	FCC_VOLUME_TOO_BIG,
	FCC_NO_MEDIA_IN_DRIVE,
	FCC_UNKNOWN15,
	FCC_UNKNOWN16,
	FCC_UNKNOWN17,
	FCC_DEVICE_NOT_READY,
	FCC_CHECKDISK_PROGRESS,
	FCC_UNKNOWN1A,
	FCC_UNKNOWN1B,
	FCC_UNKNOWN1C,
	FCC_UNKNOWN1D,
	FCC_UNKNOWN1E,
	FCC_UNKNOWN1F,
	FCC_READ_ONLY_MODE,
} FILE_SYSTEM_CALLBACK_COMMAND;

typedef struct {
	DWORD Lines;
	CHAR* Output;
} TEXTOUTPUT, *PTEXTOUTPUT;
typedef BOOLEAN(__stdcall *FILE_SYSTEM_CALLBACK)(
	FILE_SYSTEM_CALLBACK_COMMAND Command,
	ULONG                        Action,
	PVOID                        pData
	);

/* Parameter names aligned to
http://msdn.microsoft.com/en-us/library/windows/desktop/aa819439.aspx */
typedef VOID(WINAPI *FormatEx_t)(
	WCHAR*               DriveRoot,
	MEDIA_TYPE           MediaType,		// See WinIoCtl.h
	WCHAR*               FileSystemTypeName,
	WCHAR*               Label,
	BOOL                 QuickFormat,
	ULONG                DesiredUnitAllocationSize,
	FILE_SYSTEM_CALLBACK Callback
	);


typedef BOOLEAN(WINAPI* EnableVolumeCompression_t)(
	WCHAR*               DriveRoot,
	ULONG                CompressionFlags	// FILE_SYSTEM_PROP_FLAG
	);

#define utf8_to_wchar_no_alloc(src, wdest, wdest_size) \
	MultiByteToWideChar(CP_UTF8, 0, src, -1, wdest, wdest_size)

#define sfree(p) do {if (p != NULL) {free((void*)(p)); p = NULL;}} while(0)

static __inline wchar_t* utf8_to_wchar(const char* str)
{
	int size = 0;
	wchar_t* wstr = NULL;

	if (str == NULL)
		return NULL;

	// Find out the size we need to allocate for our converted string
	size = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	if (size <= 1)	// An empty string would be size 1
		return NULL;

	if ((wstr = (wchar_t*)calloc(size, sizeof(wchar_t))) == NULL)
		return NULL;

	if (utf8_to_wchar_no_alloc(str, wstr, size) != size) {
		sfree(wstr);
		return NULL;
	}
	return wstr;
}

//格式化线程  传进来的是物理磁盘号
DWORD WINAPI FormatThread(void* param);

//获取磁盘的信息用来填充结构体
BOOL GetDrivePartitionData(DWORD DriveIndex, char* FileSystemName, DWORD FileSystemNameSize, BOOL bSilent);


char* GetLogicalName(DWORD DriveIndex, BOOL bKeepTrailingBackslash, BOOL bSilent);

HANDLE GetPhysicalHandle(DWORD DriveIndex, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare);

char GetUnusedDriveLetter(void);


int GetDriveNumber(HANDLE hDrive, char* path);

BOOL GetDriveLetters(DWORD DriveIndex, char* drive_letters);

HANDLE GetLogicalHandle(DWORD DriveIndex, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare);
BOOL UnmountVolume(HANDLE hDrive);

BOOL AnalyzePBR(HANDLE hLogicalVolume);

BOOL ClearMBRGPT(HANDLE hPhysicalDrive, LONGLONG DiskSize, DWORD SectorSize, BOOL add1MB);
BOOL InitializeDisk(HANDLE hDrive);

BOOL CreatePartition(HANDLE hDrive, int partition_style, int file_system, BOOL mbr_uefi_marker, uint8_t extra_partitions);
BOOL RefreshDriveLayout(HANDLE hDrive);

BOOL WaitForLogical(DWORD DriveIndex);

BOOL FormatDrive(DWORD DriveIndex);

BOOL MountVolume(char* drive_name, char *drive_guid);
BOOL RemountVolume(char* drive_name);
BOOL FlushDrive(char drive_letter);
//这里添加一个扇区的验证数据  chengheming
BOOL WriteModifySector(HANDLE hPhysicalDrive);