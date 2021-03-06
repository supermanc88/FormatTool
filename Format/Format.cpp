// Format.cpp: 定义控制台应用程序的入口点。
//

#include "Format.h"

RUFUS_DRIVE_INFO SelectedDrive = {0};   //用来存储磁盘的信息
unsigned long ulBytesPerSector = 512;

BOOL large_drive;

int bt = 9;
int default_fs = 2;
int fs = 2;
int pt = 0;
int tt＝0; // file system, boot type, partition type, target type
BOOL lock_drive = FALSE;
DWORD FormatStatus;

int usualFormat;

/* Returns the number of bytes written or -1 on error */
int64_t write_sectors(HANDLE hDrive, uint64_t SectorSize,
	uint64_t StartSector, uint64_t nSectors,
	const void *pBuf)
{
	LARGE_INTEGER ptr;
	DWORD Size;

	if ((nSectors*SectorSize) > 0xFFFFFFFFUL)
	{
		printf("write_sectors: nSectors x SectorSize is too big\n");
		return -1;
	}
	Size = (DWORD)(nSectors*SectorSize);

	ptr.QuadPart = StartSector * SectorSize;
	if (!SetFilePointerEx(hDrive, ptr, NULL, FILE_BEGIN))
	{
		return -1;
	}

	if (!WriteFile(hDrive, pBuf, Size, &Size, NULL))
	{

		return -1;
	}
	if (Size != nSectors * SectorSize)
	{
		/* Some large drives return 0, even though all the data was written - See github #787 */
		if (large_drive && Size == 0) {
			printf("Warning: Possible short write\n");
			return 0;
		}
		printf("write_sectors:write error\n");

		return -1;
	}

	return (int64_t)Size;
}

/* Returns the number of bytes read or -1 on error */
int64_t read_sectors(HANDLE hDrive, uint64_t SectorSize,
	uint64_t StartSector, uint64_t nSectors,
	void *pBuf)
{
	LARGE_INTEGER ptr;
	DWORD Size;

	if ((nSectors*SectorSize) > 0xFFFFFFFFUL)
	{
		printf("read_sectors: nSectors x SectorSize is too big\n");
		return -1;
	}
	Size = (DWORD)(nSectors*SectorSize);

	ptr.QuadPart = StartSector * SectorSize;
	if (!SetFilePointerEx(hDrive, ptr, NULL, FILE_BEGIN))
	{

		return -1;
	}

	if ((!ReadFile(hDrive, pBuf, Size, &Size, NULL)) || (Size != nSectors * SectorSize))
	{

	}

	return (int64_t)Size;
}

int read_data(FILE *fp, uint64_t Position,
	void *pData, uint64_t Len)
{
	int r = 0;
	unsigned char *aucBuf = (unsigned char *)_mm_malloc(MAX_DATA_LEN, 16);
	FAKE_FD* fd = (FAKE_FD*)fp;
	HANDLE hDrive = (HANDLE)fd->_handle;
	uint64_t StartSector, EndSector, NumSectors;

	if (aucBuf == NULL)
		return 0;

	Position += fd->_offset;

	StartSector = Position / ulBytesPerSector;
	EndSector = (Position + Len + ulBytesPerSector - 1) / ulBytesPerSector;
	NumSectors = (size_t)(EndSector - StartSector);

	if ((NumSectors*ulBytesPerSector) > MAX_DATA_LEN)
	{
		printf("read_data: Please increase MAX_DATA_LEN in file.h\n");
		goto out;
	}

	if (Len > 0xFFFFFFFFUL)
	{
		printf("read_data: Len is too big\n");
		goto out;
	}

	if (read_sectors(hDrive, ulBytesPerSector, StartSector,
		NumSectors, aucBuf) <= 0)
		goto out;

	memcpy(pData, &aucBuf[Position - StartSector * ulBytesPerSector], (size_t)Len);

	r = 1;

out:
	_mm_free(aucBuf);
	return r;
}  /* read_data */

   /* May read/write the same sector many times, but compatible with existing ms-sys */
int write_data(FILE *fp, uint64_t Position,
	const void *pData, uint64_t Len)
{
	int r = 0;
	/* Windows' WriteFile() may require a buffer that is aligned to the sector size */
	/* TODO: We may need to increase the alignment if we get report of issues on 4K */
	unsigned char *aucBuf = (unsigned char *)_mm_malloc(MAX_DATA_LEN, 512);
	FAKE_FD* fd = (FAKE_FD*)fp;
	HANDLE hDrive = (HANDLE)fd->_handle;
	uint64_t StartSector, EndSector, NumSectors;

	if (aucBuf == NULL)
		return 0;

	Position += fd->_offset;

	StartSector = Position / ulBytesPerSector;
	EndSector = (Position + Len + ulBytesPerSector - 1) / ulBytesPerSector;
	NumSectors = EndSector - StartSector;

	if ((NumSectors*ulBytesPerSector) > MAX_DATA_LEN)
	{
		printf("write_data: Please increase MAX_DATA_LEN in file.h\n");
		goto out;
	}

	if (Len > 0xFFFFFFFFUL)
	{
		printf("write_data: Len is too big\n");
		goto out;
	}

	/* Data to write may not be aligned on a sector boundary => read into a sector buffer first */
	if (read_sectors(hDrive, ulBytesPerSector, StartSector,
		NumSectors, aucBuf) <= 0)
		goto out;

	if (!memcpy(&aucBuf[Position - StartSector * ulBytesPerSector], pData, (size_t)Len))
		goto out;

	if (write_sectors(hDrive, ulBytesPerSector, StartSector,
		NumSectors, aucBuf) <= 0)
		goto out;

	r = 1;

out:
	_mm_free(aucBuf);
	return r;
} /* write_data */

int contains_data(FILE *fp, uint64_t Position,
	const void *pData, uint64_t Len)
{
	int r = 0;
	unsigned char *aucBuf = (unsigned char *)_mm_malloc(MAX_DATA_LEN, 16);

	if (aucBuf == NULL)
		return 0;

	if (!read_data(fp, Position, aucBuf, Len))
		goto out;

	if (memcmp(pData, aucBuf, (size_t)Len))
		goto out;

	r = 1;

out:
	_mm_free(aucBuf);
	return r;
} /* contains_data */

int is_br(FILE *fp)
{
	/* A "file" is probably some kind of boot record if it contains the magic
	chars 0x55, 0xAA at position 0x1FE */
	unsigned char aucRef[] = { 0x55, 0xAA };

	return contains_data(fp, 0x1FE, aucRef, sizeof(aucRef));
} /* is_br */

int is_dos_mbr(FILE *fp)
{
#include "mbr_dos.h"

	return
		contains_data(fp, 0x0, mbr_dos_0x0, sizeof(mbr_dos_0x0)) &&
		is_br(fp);
} /* is_dos_mbr */

int is_dos_f2_mbr(FILE *fp)
{
#include "mbr_dos_f2.h"

	return
		contains_data(fp, 0x0, mbr_dos_f2_0x0, sizeof(mbr_dos_f2_0x0)) &&
		is_br(fp);
} /* is_dos_f2_mbr */

int is_95b_mbr(FILE *fp)
{
#include "mbr_95b.h"

	return
		contains_data(fp, 0x0, mbr_95b_0x0, sizeof(mbr_95b_0x0)) &&
		contains_data(fp, 0x0e0, mbr_95b_0x0e0, sizeof(mbr_95b_0x0e0)) &&
		is_br(fp);
} /* is_95b_mbr */

int is_2000_mbr(FILE *fp)
{
#include "mbr_2000.h"

	return
		contains_data(fp, 0x0, mbr_2000_0x0, MBR_2000_LANG_INDEP_LEN) &&
		is_br(fp);
} /* is_2000_mbr */

int is_vista_mbr(FILE *fp)
{
#include "mbr_vista.h"

	return
		contains_data(fp, 0x0, mbr_vista_0x0, MBR_VISTA_LANG_INDEP_LEN) &&
		is_br(fp);
} /* is_vista_mbr */

int is_win7_mbr(FILE *fp)
{
#include "mbr_win7.h"

	return
		contains_data(fp, 0x0, mbr_win7_0x0, MBR_WIN7_LANG_INDEP_LEN) &&
		is_br(fp);
} /* is_win7_mbr */

int is_rufus_mbr(FILE *fp)
{
#include "mbr_rufus.h"

	return
		contains_data(fp, 0x0, mbr_rufus_0x0, sizeof(mbr_rufus_0x0)) &&
		is_br(fp);
} /* is_rufus_mbr */

int is_reactos_mbr(FILE *fp)
{
#include "mbr_reactos.h"

	return
		contains_data(fp, 0x0, mbr_reactos_0x0, sizeof(mbr_reactos_0x0)) &&
		is_br(fp);
} /* is_reactos_mbr */

int is_grub4dos_mbr(FILE *fp)
{
#include "mbr_grub.h"

	return
		contains_data(fp, 0x0, mbr_grub_0x0, sizeof(mbr_grub_0x0)) &&
		is_br(fp);
} /* is_grub_mbr */

int is_grub2_mbr(FILE *fp)
{
#include "mbr_grub2.h"

	return
		contains_data(fp, 0x0, mbr_grub2_0x0, sizeof(mbr_grub2_0x0)) &&
		is_br(fp);
} /* is_grub2_mbr */

int is_kolibrios_mbr(FILE *fp)
{
#include "mbr_kolibri.h"

	return
		contains_data(fp, 0x0, mbr_kolibri_0x0, sizeof(mbr_kolibri_0x0)) &&
		is_br(fp);
} /* is_kolibri_mbr */

int is_syslinux_mbr(FILE *fp)
{
#include "mbr_syslinux.h"

	return
		contains_data(fp, 0x0, mbr_syslinux_0x0, sizeof(mbr_syslinux_0x0)) &&
		is_br(fp);
} /* is_syslinux_mbr */

int is_syslinux_gpt_mbr(FILE *fp)
{
#include "mbr_gpt_syslinux.h"

	return
		contains_data(fp, 0x0, mbr_gpt_syslinux_0x0,
			sizeof(mbr_gpt_syslinux_0x0)) &&
		is_br(fp);
} /* is_syslinux_gpt_mbr */

int is_zero_mbr(FILE *fp)
{
#include "mbr_zero.h"

	return
		contains_data(fp, 0x0, mbr_zero_0x0, sizeof(mbr_zero_0x0));
	/* Don't bother to check 55AA signature */
} /* is_zero_mbr */

int is_zero_mbr_not_including_disk_signature_or_copy_protect(FILE *fp)
{
#include "mbr_zero.h"

	return
		contains_data(fp, 0x0, mbr_zero_0x0, 0x1b8);
} /* is_zero_mbr_not_including_disk_signature_or_copy_protect */


int entire_fat_16_br_matches(FILE *fp)
{
#include "br_fat16_0x0.h"
#include "br_fat16_0x3e.h"

	return
		(contains_data(fp, 0x0, br_fat16_0x0, sizeof(br_fat16_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x3e, br_fat16_0x3e, sizeof(br_fat16_0x3e)));
} /* entire_fat_16_br_matches */

int entire_fat_16_fd_br_matches(FILE *fp)
{
#include "br_fat16_0x0.h"
#include "br_fat16fd_0x3e.h"

	return
		(contains_data(fp, 0x0, br_fat16_0x0, sizeof(br_fat16_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x3e, br_fat16_0x3e, sizeof(br_fat16_0x3e)));
} /* entire_fat_16_fd_br_matches */

int entire_fat_16_ros_br_matches(FILE *fp)
{
#include "br_fat16ros_0x0.h"
#include "br_fat16ros_0x3e.h"

	return
		(contains_data(fp, 0x0, br_fat16_0x0, sizeof(br_fat16_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x3e, br_fat16_0x3e, sizeof(br_fat16_0x3e)));
} /* entire_fat_16_ros_br_matches */

int entire_fat_32_br_matches(FILE *fp)
{
#include "br_fat32_0x0.h"
#include "br_fat32_0x52.h"
#include "br_fat32_0x3f0.h"

	return
		(contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
			/* Cluster information might differ between systems */
			contains_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)));
} /* entire_fat_32_br_matches */


int entire_fat_32_nt_br_matches(FILE *fp)
{
#include "br_fat32_0x0.h"
#include "br_fat32nt_0x52.h"
#include "br_fat32nt_0x3f0.h"
#include "br_fat32nt_0x1800.h"

	return
		(contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x52, br_fat32nt_0x52, sizeof(br_fat32nt_0x52)) &&
			/* Cluster information might differ between systems */
			contains_data(fp, 0x3f0, br_fat32nt_0x3f0, sizeof(br_fat32nt_0x3f0)) &&
			contains_data(fp, 0x1800, br_fat32nt_0x1800, sizeof(br_fat32nt_0x1800))
			);
} /* entire_fat_32_nt_br_matches */

int entire_fat_32_fd_br_matches(FILE *fp)
{
#include "br_fat32_0x0.h"
#include "br_fat32fd_0x52.h"
#include "br_fat32fd_0x3f0.h"

	return
		(contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x52, br_fat32_0x52, sizeof(br_fat32_0x52)) &&
			/* Cluster information might differ between systems */
			contains_data(fp, 0x3f0, br_fat32_0x3f0, sizeof(br_fat32_0x3f0)));
} /* entire_fat_32_fd_br_matches */

int entire_fat_32_ros_br_matches(FILE *fp)
{
#include "br_fat32_0x0.h"
#include "br_fat32ros_0x52.h"
#include "br_fat32ros_0x3f0.h"
#include "br_fat32ros_0x1c00.h"

	return
		(contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
			/* BIOS Parameter Block might differ between systems */
			contains_data(fp, 0x52, br_fat32ros_0x52, sizeof(br_fat32ros_0x52)) &&
			/* Cluster information might differ between systems */
			contains_data(fp, 0x3f0, br_fat32ros_0x3f0, sizeof(br_fat32ros_0x3f0)) &&
			contains_data(fp, 0x1c00, br_fat32ros_0x1c00, sizeof(br_fat32ros_0x1c00))
			);
} /* entire_fat_32_ros_br_matches */

int entire_fat_32_kos_br_matches(FILE *fp)
{
#include "br_fat32_0x0.h"
#include "br_fat32kos_0x52.h"

	return
		(contains_data(fp, 0x0, br_fat32_0x0, sizeof(br_fat32_0x0)) &&
			contains_data(fp, 0x52, br_fat32kos_0x52, sizeof(br_fat32kos_0x52)));
} /* entire_fat_32_kos_br_matches */



const struct { int(*fn)(FILE *fp); const char* str; } known_mbr[] = {
{ is_dos_mbr, "DOS/NT/95A" },
{ is_dos_f2_mbr, "DOS/NT/95A (F2)" },
{ is_95b_mbr, "Windows 95B/98/98SE/ME" },
{ is_2000_mbr, "Windows 2000/XP/2003" },
{ is_vista_mbr, "Windows Vista" },
{ is_win7_mbr, "Windows 7" },
{ is_rufus_mbr, "Rufus" },
{ is_syslinux_mbr, "Syslinux" },
{ is_reactos_mbr, "ReactOS" },
{ is_kolibrios_mbr, "KolibriOS" },
{ is_grub4dos_mbr, "Grub4DOS" },
{ is_grub2_mbr, "Grub 2.0" },
{ is_zero_mbr_not_including_disk_signature_or_copy_protect, "Zeroed" },
};

const struct { int(*fn)(FILE *fp); const char* str; } known_pbr[] = {
{ entire_fat_16_br_matches, "FAT16 DOS" },
{ entire_fat_16_fd_br_matches, "FAT16 FreeDOS" },
{ entire_fat_16_ros_br_matches, "FAT16 ReactOS" },
{ entire_fat_32_br_matches, "FAT32 DOS" },
{ entire_fat_32_nt_br_matches, "FAT32 NT" },
{ entire_fat_32_fd_br_matches, "FAT32 FreeDOS" },
{ entire_fat_32_ros_br_matches, "FAT32 ReactOS" },
{ entire_fat_32_kos_br_matches, "FAT32 KolibriOS" },
};

void set_bytes_per_sector(unsigned long ulValue)
{
	ulBytesPerSector = ulValue;
	if ((ulBytesPerSector < 512) || (ulBytesPerSector > 65536))
		ulBytesPerSector = 512;
} /* set_bytes_per_sector */

// Returns TRUE if the drive seems bootable, FALSE otherwise
BOOL AnalyzeMBR(HANDLE hPhysicalDrive, const char* TargetName)
{
	const char* mbr_name = "Master Boot Record";
	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;
	int i;

	fake_fd._handle = (char*)hPhysicalDrive;
	set_bytes_per_sector(SelectedDrive.SectorSize);

	if (!is_br(fp)) {
		printf("%s does not have an x86 %s\n", TargetName, mbr_name);
		return FALSE;
	}
	for (i = 0; i < ARRAYSIZE(known_mbr); i++) {
		if (known_mbr[i].fn(fp)) {
			printf("%s has a %s %s\n", TargetName, known_mbr[i].str, mbr_name);
			return TRUE;
		}
	}

	printf("%s has an unknown %s\n", TargetName, mbr_name);
	return TRUE;
}


//获取磁盘的信息用来填充结构体
BOOL GetDrivePartitionData(DWORD DriveIndex, char* FileSystemName, DWORD FileSystemNameSize, BOOL bSilent /*FALSE*/)
{
	// MBR partition types that can be mounted in Windows
	const uint8_t mbr_mountable[] = { 0x01, 0x04, 0x06, 0x07, 0x0b, 0x0c, 0x0e, 0xef };
	BOOL r, ret = FALSE, isUefiNtfs;
	HANDLE hPhysical;
	DWORD size, i, j, super_floppy_disk = FALSE;
	BYTE geometry[256] = { 0 }, layout[4096] = { 0 }, part_type;
	PDISK_GEOMETRY_EX DiskGeometry = (PDISK_GEOMETRY_EX)(void*)geometry;
	PDRIVE_LAYOUT_INFORMATION_EX DriveLayout = (PDRIVE_LAYOUT_INFORMATION_EX)(void*)layout;
	char *volume_name, *buf, tmp[256];

	if (FileSystemName == NULL)
		return FALSE;

	SelectedDrive.nPartitions = 0;
	// Populate the filesystem data
	FileSystemName[0] = 0;
	volume_name = GetLogicalName(DriveIndex, TRUE, FALSE);
	if ((volume_name == NULL) || (!GetVolumeInformationA(volume_name, NULL, 0, NULL, NULL, NULL, FileSystemName, FileSystemNameSize))) {
	}
	safe_free(volume_name);

	hPhysical = GetPhysicalHandle(DriveIndex, FALSE, FALSE, TRUE);
	if (hPhysical == INVALID_HANDLE_VALUE)
		return 0;

	r = DeviceIoControl(hPhysical, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
		NULL, 0, geometry, sizeof(geometry), &size, NULL);
	if (!r || size <= 0) {
		printf("Could not get geometry for drive 0x%02x\n", DriveIndex);
		safe_closehandle(hPhysical);
		return 0;
	}
	SelectedDrive.DiskSize = DiskGeometry->DiskSize.QuadPart;
	SelectedDrive.SectorSize = DiskGeometry->Geometry.BytesPerSector;
	SelectedDrive.FirstDataSector = MAXDWORD;
	if (SelectedDrive.SectorSize < 512) {
		printf("Warning: Drive 0x%02x reports a sector size of %d - Correcting to 512 bytes.\n",
			DriveIndex, SelectedDrive.SectorSize);
		SelectedDrive.SectorSize = 512;
	}
	SelectedDrive.SectorsPerTrack = DiskGeometry->Geometry.SectorsPerTrack;
	SelectedDrive.MediaType = DiskGeometry->Geometry.MediaType;


	r = DeviceIoControl(hPhysical, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
		NULL, 0, layout, sizeof(layout), &size, NULL);
	if (!r || size <= 0) {
		printf("Could not get layout for drive 0x%02x\n", DriveIndex);
		safe_closehandle(hPhysical);
		return 0;
	}

#if defined(__GNUC__)
	// GCC 4.9 bugs us about the fact that MS defined an expandable array as array[1]
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif
	switch (DriveLayout->PartitionStyle) {
	case PARTITION_STYLE_MBR:
		SelectedDrive.PartitionStyle = PARTITION_STYLE_MBR;
		for (i = 0; i < DriveLayout->PartitionCount; i++) {
			if (DriveLayout->PartitionEntry[i].Mbr.PartitionType != PARTITION_ENTRY_UNUSED) {
				SelectedDrive.nPartitions++;
			}
		}
		// Detect drives that are using the whole disk as a single partition
		if ((DriveLayout->PartitionEntry[0].Mbr.PartitionType != PARTITION_ENTRY_UNUSED) &&
			(DriveLayout->PartitionEntry[0].StartingOffset.QuadPart == 0LL)) {
			super_floppy_disk = TRUE;
		}
		else {
			printf("Partition type: MBR, NB Partitions: %d\n", SelectedDrive.nPartitions);
			SelectedDrive.has_mbr_uefi_marker = (DriveLayout->Mbr.Signature == MBR_UEFI_MARKER);
			printf("Disk ID: 0x%08X %s\n", DriveLayout->Mbr.Signature, SelectedDrive.has_mbr_uefi_marker ? "(UEFI target)" : "");
			AnalyzeMBR(hPhysical, "Drive");
		}
		for (i = 0; i < DriveLayout->PartitionCount; i++) {
			isUefiNtfs = FALSE;
			if (DriveLayout->PartitionEntry[i].Mbr.PartitionType != PARTITION_ENTRY_UNUSED) {
				part_type = DriveLayout->PartitionEntry[i].Mbr.PartitionType;
				if (part_type == 0xef) {
					// Check the FAT label to see if we're dealing with an UEFI_NTFS partition
					buf = (char *)calloc(SelectedDrive.SectorSize, 1);
					if (buf != NULL) {
						if (SetFilePointerEx(hPhysical, DriveLayout->PartitionEntry[i].StartingOffset, NULL, FILE_BEGIN) &&
							ReadFile(hPhysical, buf, SelectedDrive.SectorSize, &size, NULL)) {
							isUefiNtfs = (strncmp(&buf[0x2B], "UEFI_NTFS", 9) == 0);
						}
						free(buf);
					}
				}
				printf("Partition %d%s:\n", i + (super_floppy_disk ? 0 : 1), isUefiNtfs ? " (UEFI:NTFS)" : "");
				for (j = 0; j < ARRAYSIZE(mbr_mountable); j++) {
					if (part_type == mbr_mountable[j]) {
						ret = TRUE;
						break;
					}
				}

				// sprintf("  GUID: %s", GuidToString(&DriveLayout->PartitionEntry[i].Mbr.PartitionId));
				SelectedDrive.FirstDataSector = min(SelectedDrive.FirstDataSector,
					(DWORD)(DriveLayout->PartitionEntry[i].StartingOffset.QuadPart / SelectedDrive.SectorSize));
				if ((part_type == RUFUS_EXTRA_PARTITION_TYPE) || (isUefiNtfs))
					// This is a partition Rufus created => we can safely ignore it
					--SelectedDrive.nPartitions;
				if (part_type == 0xee)	// Flag a protective MBR for non GPT platforms (XP)
					SelectedDrive.has_protective_mbr = TRUE;
			}
		}
		break;
	default:
		SelectedDrive.PartitionStyle = PARTITION_STYLE_MBR;
		printf("Partition type: RAW\n");
		break;
	}
// #if defined(__GNUC__)
// #pragma GCC diagnostic warning "-Warray-bounds"
// #endif
// 	safe_closehandle(hPhysical);

	return ret;
}




char* GetLogicalName(DWORD DriveIndex, BOOL bKeepTrailingBackslash, BOOL bSilent)
{
	BOOL success = FALSE;
	char volume_name[MAX_PATH];
	HANDLE hDrive = INVALID_HANDLE_VALUE, hVolume = INVALID_HANDLE_VALUE;
	size_t len;
	char path[MAX_PATH];
	VOLUME_DISK_EXTENTS_REDEF DiskExtents;
	DWORD size;
	UINT drive_type;
	int i, j;
	static const char* ignore_device[] = { "\\Device\\CdRom", "\\Device\\Floppy" };
	static const char* volume_start = "\\\\?\\";


	for (i = 0; hDrive == INVALID_HANDLE_VALUE; i++) {
		if (i == 0) {
			hVolume = FindFirstVolumeA(volume_name, sizeof(volume_name));
			if (hVolume == INVALID_HANDLE_VALUE) {
				goto out;
			}
		}
		else {
			if (!FindNextVolumeA(hVolume, volume_name, sizeof(volume_name))) {
				if (GetLastError() != ERROR_NO_MORE_FILES) {
				}
				goto out;
			}
		}

		// Sanity checks
		len = safe_strlen(volume_name);
		if ((len <= 1) || (safe_strnicmp(volume_name, volume_start, 4) != 0) || (volume_name[len - 1] != '\\')) {
			continue;
		}

		drive_type = GetDriveTypeA(volume_name);
		if ((drive_type != DRIVE_REMOVABLE) && (drive_type != DRIVE_FIXED))
			continue;

		volume_name[len - 1] = 0;

		if (QueryDosDeviceA(&volume_name[4], path, sizeof(path)) == 0) {
			continue;
		}

		for (j = 0; (j < ARRAYSIZE(ignore_device)) &&
			(_strnicmp(path, ignore_device[j], safe_strlen(ignore_device[j])) != 0); j++);
		if (j < ARRAYSIZE(ignore_device)) {
			continue;
		}

		hDrive = CreateFileA(volume_name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDrive == INVALID_HANDLE_VALUE) {
			continue;
		}

		if ((!DeviceIoControl(hDrive, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
			&DiskExtents, sizeof(DiskExtents), &size, NULL)) || (size <= 0)) {
			safe_closehandle(hDrive);
			continue;
		}
		safe_closehandle(hDrive);
		if ((DiskExtents.NumberOfDiskExtents >= 1) && (DiskExtents.Extents[0].DiskNumber == DriveIndex)) {
			if (bKeepTrailingBackslash)
				volume_name[len - 1] = '\\';
			success = TRUE;
			break;
		}
	}

out:
	if (hVolume != INVALID_HANDLE_VALUE)
		FindVolumeClose(hVolume);
	return (success) ? safe_strdup(volume_name) : NULL;
}

HANDLE GetHandle(char* Path, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare)
{
	int i;
	BYTE access_mask = 0;
	DWORD size;
	uint64_t EndTime;
	HANDLE hDrive = INVALID_HANDLE_VALUE;
	char DevPath[MAX_PATH];

	if ((safe_strlen(Path) < 5) || (Path[0] != '\\') || (Path[1] != '\\') || (Path[3] != '\\'))
		goto out;

	// Resolve a device path, so that we can look for that handle in case of access issues.
	if (QueryDosDeviceA(&Path[4], DevPath, sizeof(DevPath)) == 0)
		strcpy(DevPath, "???");

	for (i = 0; i < DRIVE_ACCESS_RETRIES; i++) {
		// Try without FILE_SHARE_WRITE (unless specifically requested) so that
		// we won't be bothered by the OS or other apps when we set up our data.
		// However this means we might have to wait for an access gap...
		// We keep FILE_SHARE_READ though, as this shouldn't hurt us any, and is
		// required for enumeration.
		hDrive = CreateFileA(Path, GENERIC_READ | (bWriteAccess ? GENERIC_WRITE : 0),
			FILE_SHARE_READ | (bWriteShare ? FILE_SHARE_WRITE : 0),
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDrive != INVALID_HANDLE_VALUE)
			break;
		if ((GetLastError() != ERROR_SHARING_VIOLATION) && (GetLastError() != ERROR_ACCESS_DENIED))
			break;
		if (i == 0) {
			printf("Waiting for access on %s [%s]...\n", Path, DevPath);
		}
		else if (!bWriteShare && (i > DRIVE_ACCESS_RETRIES / 3)) {
			// If we can't seem to get a hold of the drive for some time, try to enable FILE_SHARE_WRITE...
			printf("Warning: Could not obtain exclusive rights. Retrying with write sharing enabled...\n");
			bWriteShare = TRUE;
			// Try to report the process that is locking the drive
			// We also use bit 6 as a flag to indicate that SearchProcess was called.
			//access_mask = SearchProcess(DevPath, 5000, TRUE, TRUE, FALSE) | 0x40;
		}
		Sleep(DRIVE_ACCESS_TIMEOUT / DRIVE_ACCESS_RETRIES);
	}
	if (hDrive == INVALID_HANDLE_VALUE) {
		//printf("Could not open %s: %s", Path, WindowsErrorString());
		goto out;
	}

	if (bWriteAccess) {
		printf("Opened %s for %s write access\n", Path, bWriteShare ? "shared" : "exclusive");
	}

	if (bLockDrive) {
		if (DeviceIoControl(hDrive, FSCTL_ALLOW_EXTENDED_DASD_IO, NULL, 0, NULL, 0, &size, NULL)) {
			printf("I/O boundary checks disabled\n");
		}

		printf("Requesting lock...\n");
		EndTime = GetTickCount64() + DRIVE_ACCESS_TIMEOUT;
		do {
			if (DeviceIoControl(hDrive, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &size, NULL))
				goto out;
			//if (IS_ERROR(FormatStatus))	// User cancel
			//	break;
			Sleep(DRIVE_ACCESS_TIMEOUT / DRIVE_ACCESS_RETRIES);
		} while (GetTickCount64() < EndTime);
		//// If we reached this section, either we didn't manage to get a lock or the user cancelled
		//printf("Could not lock access to %s: %s", Path, WindowsErrorString());
		//// See if we can report the processes are accessing the drive
		//if (!IS_ERROR(FormatStatus) && (access_mask == 0))
		//	access_mask = SearchProcess(DevPath, 5000, TRUE, TRUE, FALSE);
		// Try to continue if the only access rights we saw were for read-only
		if ((access_mask & 0x07) != 0x01)
			safe_closehandle(hDrive);
	}

out:
	return hDrive;
}


HANDLE GetPhysicalHandle(DWORD DriveIndex, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare)
{
	HANDLE hPhysical = INVALID_HANDLE_VALUE;
	BOOL success = FALSE;
	char physical_name[24];

	static_sprintf(physical_name, "\\\\.\\PHYSICALDRIVE%lu", DriveIndex);
	success = TRUE;

	char* PhysicalPath = safe_strdup(physical_name);


	hPhysical = GetHandle(PhysicalPath, bLockDrive, bWriteAccess, bWriteShare);
	safe_free(PhysicalPath);
	return hPhysical;
}

char GetUnusedDriveLetter(void)
{
	DWORD size;
	char drive_letter = 'Z' + 1, *drive, drives[26 * 4 + 1];	/* "D:\", "E:\", etc., plus one NUL */

	size = GetLogicalDriveStringsA(sizeof(drives), drives);
	if (size == 0) {
		goto out;
	}
	if (size > sizeof(drives)) {
		printf("GetLogicalDriveStrings: Buffer too small (required %d vs. %d)\n", size, sizeof(drives));
		goto out;
	}

	for (drive_letter = 'C'; drive_letter <= 'Z'; drive_letter++) {
		for (drive = drives; *drive; drive += safe_strlen(drive) + 1) {
			if (!isalpha(*drive))
				continue;
			if (drive_letter == (char)toupper((int)*drive))
				break;
		}
		if (!*drive)
			break;
	}

out:
	return (drive_letter > 'Z') ? 0 : drive_letter;
}


/*
* Who would have thought that Microsoft would make it so unbelievably hard to
* get the frickin' device number for a drive? You have to use TWO different
* methods to have a chance to get it!
*/
int GetDriveNumber(HANDLE hDrive, char* path)
{
	STORAGE_DEVICE_NUMBER_REDEF DeviceNumber;
	VOLUME_DISK_EXTENTS_REDEF DiskExtents;
	DWORD size;
	int r = -1;

	if (!DeviceIoControl(hDrive, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
		&DiskExtents, sizeof(DiskExtents), &size, NULL) || (size <= 0) || (DiskExtents.NumberOfDiskExtents < 1)) {
		// DiskExtents are NO_GO (which is the case for external USB HDDs...)
		if (!DeviceIoControl(hDrive, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
			&DeviceNumber, sizeof(DeviceNumber), &size, NULL) || (size <= 0)) {
			return -1;
		}
		r = (int)DeviceNumber.DeviceNumber;
	}
	else if (DiskExtents.NumberOfDiskExtents >= 2) {
		printf("Ignoring drive '%s' as it spans multiple disks (RAID?)\n", path);
		return -1;
	}
	else {
		r = (int)DiskExtents.Extents[0].DiskNumber;
	}
	if (r >= 64) {
		printf("Device Number for device %s is too big (%d) - ignoring device\n", path, r);
		return -1;
	}
	return r;
}

NtQueryVolumeInformationFile_t pfNtQueryVolumeInformationFile = NULL;
FormatEx_t pfFormatEx = NULL;
EnableVolumeCompression_t pfEnableVolumeCompression = NULL;


BOOL GetDriveLetters(DWORD DriveIndex, char* drive_letters)
{
	DWORD size;
	BOOL r = FALSE;
	HANDLE hDrive = INVALID_HANDLE_VALUE;
	UINT _drive_type;
	IO_STATUS_BLOCK io_status_block;
	FILE_FS_DEVICE_INFORMATION file_fs_device_info;
	int i = 0, drive_number;
	char *drive, drives[26 * 4 + 1];	/* "D:\", "E:\", etc., plus one NUL */
	char logical_drive[] = "\\\\.\\#:";


	pfNtQueryVolumeInformationFile = (NtQueryVolumeInformationFile_t)GetProcAddress(GetLibraryHandle("Ntdll"), "NtQueryVolumeInformationFile");

	if (drive_letters != NULL)
		drive_letters[0] = 0;



	// This call is weird... The buffer needs to have an extra NUL, but you're
	// supposed to provide the size without the extra NUL. And the returned size
	// does not include the NUL either *EXCEPT* if your buffer is too small...
	// But then again, this doesn't hold true if you have a 105 byte buffer and
	// pass a 4*26=104 size, as the the call will return 105 (i.e. *FAILURE*)
	// instead of 104 as it should => screw Microsoft: We'll include the NUL
	// always, as each drive string is at least 4 chars long anyway.
	size = GetLogicalDriveStringsA(sizeof(drives), drives);
	if (size == 0) {
		goto out;
	}
	if (size > sizeof(drives)) {
		goto out;
	}

	r = TRUE;	// Required to detect drives that don't have volumes assigned
	for (drive = drives; *drive; drive += safe_strlen(drive) + 1) {
		if (!isalpha(*drive))
			continue;
		*drive = (char)toupper((int)*drive);

		// IOCTL_STORAGE_GET_DEVICE_NUMBER's STORAGE_DEVICE_NUMBER.DeviceNumber is
		// not unique! An HDD, a DVD and probably other drives can have the same
		// value there => Use GetDriveType() to filter out unwanted devices.
		// See https://github.com/pbatard/rufus/issues/32#issuecomment-3785956
		_drive_type = GetDriveTypeA(drive);

		if ((_drive_type != DRIVE_REMOVABLE) && (_drive_type != DRIVE_FIXED))
			continue;

		static_sprintf(logical_drive, "\\\\.\\%c:", drive[0]);
		hDrive = CreateFileA(logical_drive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDrive == INVALID_HANDLE_VALUE) {
			//			uprintf("Warning: could not open drive %c: %s", drive[0], WindowsErrorString());
			continue;
		}

		// Eliminate floppy drives
		if ((pfNtQueryVolumeInformationFile != NULL) &&
			(pfNtQueryVolumeInformationFile(hDrive, &io_status_block, &file_fs_device_info,
				sizeof(file_fs_device_info), FileFsDeviceInformation) == NO_ERROR) &&
				(file_fs_device_info.Characteristics & FILE_FLOPPY_DISKETTE)) {
			continue;
		}

		drive_number = GetDriveNumber(hDrive, logical_drive);
		safe_closehandle(hDrive);
		if (drive_number == DriveIndex) {
			r = TRUE;
			if (drive_letters != NULL)
				drive_letters[i++] = *drive;

		}
	}

out:
	if (drive_letters != NULL)
		drive_letters[i] = 0;
	return r;
}


HANDLE GetLogicalHandle(DWORD DriveIndex, BOOL bLockDrive, BOOL bWriteAccess, BOOL bWriteShare)
{
	HANDLE hLogical = INVALID_HANDLE_VALUE;
	char* LogicalPath = GetLogicalName(DriveIndex, FALSE, FALSE);

	if (LogicalPath == NULL) {
		printf("No logical drive found (unpartitioned?)\n");
		return NULL;
	}

	hLogical = GetHandle(LogicalPath, bLockDrive, bWriteAccess, bWriteShare);
	free(LogicalPath);
	return hLogical;
}


/*
* Unmount of volume using the DISMOUNT_VOLUME ioctl
*/
BOOL UnmountVolume(HANDLE hDrive)
{
	DWORD size;

	if (!DeviceIoControl(hDrive, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &size, NULL)) {
		return FALSE;
	}
	return TRUE;
}

int is_fat_16_br(FILE *fp)
{
	/* A "file" is probably some kind of FAT16 boot record if it contains the
	magic chars 0x55, 0xAA at positions 0x1FE */
	unsigned char aucRef[] = { 0x55, 0xAA };
	unsigned char aucMagic[] = { 'M','S','W','I','N','4','.','1' };

	if (!contains_data(fp, 0x1FE, aucRef, sizeof(aucRef)))
		return 0;
	if (!contains_data(fp, 0x03, aucMagic, sizeof(aucMagic)))
		return 0;
	return 1;
} /* is_fat_16_br */

int is_fat_32_br(FILE *fp)
{
	/* A "file" is probably some kind of FAT32 boot record if it contains the
	magic chars 0x55, 0xAA at positions 0x1FE, 0x3FE and 0x5FE */
	unsigned char aucRef[] = { 0x55, 0xAA };
	unsigned char aucMagic[] = { 'M','S','W','I','N','4','.','1' };
	int i;

	for (i = 0; i<3; i++)
		if (!contains_data(fp, 0x1FE + i * 0x200, aucRef, sizeof(aucRef)))
			return 0;
	if (!contains_data(fp, 0x03, aucMagic, sizeof(aucMagic)))
		return 0;
	return 1;
} /* is_fat_32_br */

static int write_bootmark(FILE *fp)
{
	unsigned char aucRef[] = { 0x55, 0xAA };
	unsigned long pos = 0x1FE;

	for (pos = 0x1FE; pos < ulBytesPerSector; pos += 0x200) {
		if (!write_data(fp, pos, aucRef, sizeof(aucRef)))
			return 0;
	}
	return 1;
}
int write_win7_mbr(FILE *fp)
{
#include "mbr_win7.h"

	return
		write_data(fp, 0x0, mbr_win7_0x0, sizeof(mbr_win7_0x0)) &&
		write_bootmark(fp);
} /* write_win7_mbr */


BOOL AnalyzePBR(HANDLE hLogicalVolume)
{
	const char* pbr_name = "Partition Boot Record";
	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;
	int i;

	fake_fd._handle = (char*)hLogicalVolume;
	set_bytes_per_sector(SelectedDrive.SectorSize);

	if (!is_br(fp)) {
		printf("Volume does not have an x86 %s\n", pbr_name);
		return FALSE;
	}

	if (is_fat_16_br(fp) || is_fat_32_br(fp)) {
		for (i = 0; i < ARRAYSIZE(known_pbr); i++) {
			if (known_pbr[i].fn(fp)) {
				printf("Drive has a %s %s\n", known_pbr[i].str, pbr_name);
				return TRUE;
			}
		}
		printf("Volume has an unknown FAT16 or FAT32 %s\n", pbr_name);
	}
	else {
		printf("Volume has an unknown %s\n", pbr_name);
	}
	return TRUE;
}


BOOL ClearMBRGPT(HANDLE hPhysicalDrive, LONGLONG DiskSize, DWORD SectorSize, BOOL add1MB)
{
	BOOL r = FALSE;
	uint64_t i, j, last_sector = DiskSize / SectorSize, num_sectors_to_clear;
	unsigned char* pBuf = (unsigned char*)calloc(SectorSize, 1);

	if (pBuf == NULL) {
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}
	// http://en.wikipedia.org/wiki/GUID_Partition_Table tells us we should clear 34 sectors at the
	// beginning and 33 at the end. We bump these values to MAX_SECTORS_TO_CLEAR each end to help
	// with reluctant access to large drive.

	// We try to clear at least 1MB + the PBR when Large FAT32 is selected (add1MB), but
	// don't do it otherwise, as it seems unnecessary and may take time for slow drives.
	// Also, for various reasons (one of which being that Windows seems to have issues
	// with GPT drives that contain a lot of small partitions) we try not not to clear
	// sectors further than the lowest partition already residing on the disk.
	num_sectors_to_clear = min(SelectedDrive.FirstDataSector, (DWORD)((add1MB ? 2048 : 0) + MAX_SECTORS_TO_CLEAR));
	// Special case for big floppy disks (FirstDataSector = 0)
	if (num_sectors_to_clear < 4)
		num_sectors_to_clear = (DWORD)((add1MB ? 2048 : 0) + MAX_SECTORS_TO_CLEAR);

	printf("Erasing %d sectors\n", num_sectors_to_clear);
	for (i = 0; i < num_sectors_to_clear; i++) {
		for (j = 1; j <= WRITE_RETRIES; j++) {
			if (IS_ERROR(FormatStatus))
				goto out;
			if (write_sectors(hPhysicalDrive, SectorSize, i, 1, pBuf) != SectorSize) {
				if (j < WRITE_RETRIES) {
					printf("Retrying in %d seconds...\n", WRITE_TIMEOUT / 1000);
					Sleep(WRITE_TIMEOUT);
				}
				else
					goto out;
			}
		}
	}
	for (i = last_sector - MAX_SECTORS_TO_CLEAR; i < last_sector; i++) {
		for (j = 1; j <= WRITE_RETRIES; j++) {
			if (IS_ERROR(FormatStatus))
				goto out;
			if (write_sectors(hPhysicalDrive, SectorSize, i, 1, pBuf) != SectorSize) {
				if (j < WRITE_RETRIES) {
					printf("Retrying in %d seconds...\n", WRITE_TIMEOUT / 1000);
					Sleep(WRITE_TIMEOUT);
				}
				else
					goto out;
			}
		}
	}
	r = TRUE;

out:
	safe_free(pBuf);
	return r;
}


/* Initialize disk for partitioning */
BOOL InitializeDisk(HANDLE hDrive)
{
	BOOL r;
	DWORD size;
	CREATE_DISK CreateDisk = { PARTITION_STYLE_RAW,{ { 0 } } };


	size = sizeof(CreateDisk);
	r = DeviceIoControl(hDrive, IOCTL_DISK_CREATE_DISK,
		(BYTE*)&CreateDisk, size, NULL, 0, &size, NULL);
	if (!r) {
		safe_closehandle(hDrive);
		return FALSE;
	}

	r = DeviceIoControl(hDrive, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &size, NULL);
	if (!r) {
		safe_closehandle(hDrive);
		return FALSE;
	}

	return TRUE;
}


BOOL CreatePartition(HANDLE hDrive, int partition_style, int file_system, BOOL mbr_uefi_marker, uint8_t extra_partitions)
{
	const char* PartitionTypeName[] = { "MBR", "GPT", "SFD" };
	unsigned char* buffer;
	size_t uefi_ntfs_size = 0;
	CREATE_DISK CreateDisk = { PARTITION_STYLE_RAW,{ { 0 } } };
	DRIVE_LAYOUT_INFORMATION_EX4 DriveLayoutEx = { 0 };
	BOOL r;
	DWORD i, size, bufsize, pn = 0;
	LONGLONG main_part_size_in_sectors, extra_part_size_in_tracks = 0, ms_efi_size;
	const LONGLONG bytes_per_track = ((LONGLONG)SelectedDrive.SectorsPerTrack) * SelectedDrive.SectorSize;



	DriveLayoutEx.PartitionEntry[pn].StartingOffset.QuadPart = MB;


	if (usualFormat)
	{
		main_part_size_in_sectors = (SelectedDrive.DiskSize - DriveLayoutEx.PartitionEntry[pn].StartingOffset.QuadPart) /
			// Need 33 sectors at the end for secondary GPT
			SelectedDrive.SectorSize - ((partition_style == PARTITION_STYLE_GPT) ? 33 : 0);
	}
	else
	{
		// chengheming 这里修改格式化大小为10M
		main_part_size_in_sectors = 10 * 1024 * 1024 / 512;
	}


	if (main_part_size_in_sectors <= 0)
		return FALSE;

	DriveLayoutEx.PartitionEntry[pn].PartitionLength.QuadPart = main_part_size_in_sectors * SelectedDrive.SectorSize;
	if (partition_style == PARTITION_STYLE_MBR) {
		DriveLayoutEx.PartitionEntry[pn].Mbr.BootIndicator = (bt != BT_NON_BOOTABLE);
		switch (file_system) {
		case FS_FAT16:
			DriveLayoutEx.PartitionEntry[pn].Mbr.PartitionType = 0x0e;	// FAT16 LBA
			break;
		case FS_NTFS:
		case FS_EXFAT:
		case FS_UDF:
		case FS_REFS:
			DriveLayoutEx.PartitionEntry[pn].Mbr.PartitionType = 0x07;
			break;
		case FS_FAT32:
			DriveLayoutEx.PartitionEntry[pn].Mbr.PartitionType = 0x0c;	// FAT32 LBA
			break;
		default:
			printf("Unsupported file system\n");
			return FALSE;
		}
	}
// 	else {
// 		DriveLayoutEx.PartitionEntry[pn].Gpt.PartitionType = PARTITION_BASIC_DATA_GUID;
// 		IGNORE_RETVAL(CoCreateGuid(&DriveLayoutEx.PartitionEntry[pn].Gpt.PartitionId));
// 		wcscpy(DriveLayoutEx.PartitionEntry[pn].Gpt.Name, L"Microsoft Basic Data");
// 	}
	pn++;

	// Initialize the remaining partition data
	for (i = 0; i < pn; i++) {
		DriveLayoutEx.PartitionEntry[i].PartitionNumber = i + 1;
		DriveLayoutEx.PartitionEntry[i].PartitionStyle = (PARTITION_STYLE)partition_style;
		DriveLayoutEx.PartitionEntry[i].RewritePartition = TRUE;
	}

	switch (partition_style) {
	case PARTITION_STYLE_MBR:
		CreateDisk.PartitionStyle = PARTITION_STYLE_MBR;
		// If MBR+UEFI is selected, write an UEFI marker in lieu of the regular MBR signature.
		// This helps us reselect the partition scheme option that was used when creating the
		// drive in Rufus. As far as I can tell, Windows doesn't care much if this signature
		// isn't unique for USB drives.
		CreateDisk.Mbr.Signature = mbr_uefi_marker ? MBR_UEFI_MARKER : (DWORD)GetTickCount64();

		DriveLayoutEx.PartitionStyle = PARTITION_STYLE_MBR;
		DriveLayoutEx.PartitionCount = 4;	// Must be multiple of 4 for MBR
		DriveLayoutEx.Type.Mbr.Signature = CreateDisk.Mbr.Signature;
		// TODO: CHS fixup (32 sectors/track) through a cheat mode, if requested
		// NB: disk geometry is computed by BIOS & co. by finding a match between LBA and CHS value of first partition
		//     ms-sys's write_partition_number_of_heads() and write_partition_start_sector_number() can be used if needed
		break;
	}
	// If you don't call IOCTL_DISK_CREATE_DISK, the next call will fail
	size = sizeof(CreateDisk);
	r = DeviceIoControl(hDrive, IOCTL_DISK_CREATE_DISK, (BYTE*)&CreateDisk, size, NULL, 0, &size, NULL);
	if (!r) {
		return FALSE;
	}

	size = sizeof(DriveLayoutEx) - ((partition_style == PARTITION_STYLE_GPT) ? ((4 - pn) * sizeof(PARTITION_INFORMATION_EX)) : 0);
	r = DeviceIoControl(hDrive, IOCTL_DISK_SET_DRIVE_LAYOUT_EX, (BYTE*)&DriveLayoutEx, size, NULL, 0, &size, NULL);
	if (!r) {
		return FALSE;
	}

	if (!RefreshDriveLayout(hDrive))
		return FALSE;

	return TRUE;
}


BOOL RefreshDriveLayout(HANDLE hDrive)
{
	BOOL r;
	DWORD size;

	// Diskpart does call the following IOCTL this after updating the partition table, so we do too
	r = DeviceIoControl(hDrive, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &size, NULL);
	if (!r)
	return r;
}


BOOL WaitForLogical(DWORD DriveIndex)
{
	uint64_t EndTime;
	char* LogicalPath = NULL;

	// GetLogicalName() calls may be slow, so use the system time to
	// make sure we don't spend more than DRIVE_ACCESS_TIMEOUT in wait.
	EndTime = GetTickCount64() + DRIVE_ACCESS_TIMEOUT;
	do {
		LogicalPath = GetLogicalName(DriveIndex, FALSE, TRUE);
		if (LogicalPath != NULL) {
			free(LogicalPath);
			return TRUE;
		}
		if (IS_ERROR(FormatStatus))	// User cancel
			return FALSE;
		Sleep(DRIVE_ACCESS_TIMEOUT / DRIVE_ACCESS_RETRIES);
	} while (GetTickCount64() < EndTime);
	printf("Timeout while waiting for logical drive\n");
	return FALSE;
}


static BOOLEAN __stdcall FormatExCallback(FILE_SYSTEM_CALLBACK_COMMAND Command, DWORD Action, PVOID pData)
{
	DWORD* percent;
	if (IS_ERROR(FormatStatus))
		return FALSE;

	switch (Command) {
	case FCC_PROGRESS:
		percent = (DWORD*)pData;
		break;
	case FCC_STRUCTURE_PROGRESS:	// No progress on quick format

		break;
	case FCC_DONE:
		if (*(BOOLEAN*)pData == FALSE) {
			printf("Error while formatting\n");
			FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_GEN_FAILURE;
		}
		break;
	case FCC_DONE_WITH_STRUCTURE:	// We get this message when formatting Small FAT16
									// pData Seems to be a struct with at least one (32 BIT!!!) string pointer to the size in MB
									// uprintf("Done with that sort of thing: Action=%d pData=%0p\n", Action, pData);
									// /!\ THE FOLLOWING ONLY WORKS ON VISTA OR LATER - DO NOT ENABLE ON XP!
									// DumpBufferHex(pData, 8);
									// uprintf("Volume size: %s MB\n", (char*)(LONG_PTR)(*(ULONG32*)pData));
		break;
	case FCC_INCOMPATIBLE_FILE_SYSTEM:
		printf("Incompatible File System\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) ;
		break;
	case FCC_ACCESS_DENIED:
		printf("Access denied\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_ACCESS_DENIED;
		break;
	case FCC_MEDIA_WRITE_PROTECTED:
		printf("Media is write protected\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_WRITE_PROTECT;
		break;
	case FCC_VOLUME_IN_USE:
		printf("Volume is in use\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_DEVICE_IN_USE;
		break;
	case FCC_DEVICE_NOT_READY:
		printf("The device is not ready\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NOT_READY;
		break;
	case FCC_CANT_QUICK_FORMAT:
		printf("Cannot quick format this volume\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE);
		break;
	case FCC_BAD_LABEL:
		printf("Bad label\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_LABEL_TOO_LONG;
		break;
	case FCC_OUTPUT:
		printf("%s\n", ((PTEXTOUTPUT)pData)->Output);
		break;
	case FCC_CLUSTER_SIZE_TOO_BIG:
	case FCC_CLUSTER_SIZE_TOO_SMALL:
		printf("Unsupported cluster size\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE);
		break;
	case FCC_VOLUME_TOO_BIG:
	case FCC_VOLUME_TOO_SMALL:
		printf("Volume is too %s\n", (Command == FCC_VOLUME_TOO_BIG) ? "big" : "small");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) ;
		break;
	case FCC_NO_MEDIA_IN_DRIVE:
		printf("No media in drive\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NO_MEDIA_IN_DRIVE;
		break;
	default:
		printf("FormatExCallback: Received unhandled command 0x02%X - aborting\n", Command);
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NOT_SUPPORTED;
		break;
	}
	return (!IS_ERROR(FormatStatus));
}


static BOOL FormatDrive(DWORD DriveIndex)
{
	BOOL r = FALSE;
	pfFormatEx = (FormatEx_t)GetProcAddress(GetLibraryHandle("Fmifs"), "FormatEx");
	pfEnableVolumeCompression = (EnableVolumeCompression_t)GetProcAddress(GetLibraryHandle("Fmifs"), "EnableVolumeCompression");

	char FSType[64] = "NTFS";
	char path[MAX_PATH];
	char *locale, *VolumeName = NULL;
	WCHAR* wVolumeName = NULL;
	WCHAR wFSType[64] = L"NTFS";
	WCHAR wLabel[64] = L"";
	ULONG ulClusterSize;
	size_t i, index;

	// Skip the RIGHT_TO_LEFT_EMBEDDING mark from LTR languages
	index = (strncmp(FSType, RIGHT_TO_LEFT_EMBEDDING, sizeof(RIGHT_TO_LEFT_EMBEDDING) - 1) == 0) ? (sizeof(RIGHT_TO_LEFT_EMBEDDING) - 1) : 0;
	// Might have a (Default) suffix => remove it
	for (i = strlen(FSType); i > 2; i--) {
		if (FSType[i] == '(') {
			FSType[i - 1] = 0;
			break;
		}
	}

	VolumeName = GetLogicalName(DriveIndex, TRUE, TRUE);
	wVolumeName = utf8_to_wchar(VolumeName);
	if (wVolumeName == NULL) {
		printf("Could not read volume name\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_GEN_FAILURE;
		goto out;
	}
	// Hey, nice consistency here, Microsoft! -  FormatEx() fails if wVolumeName has
	// a trailing backslash, but EnableCompression() fails without...
	wVolumeName[wcslen(wVolumeName) - 1] = 0;		// Remove trailing backslash

													// Check if Windows picked the UEFI:NTFS partition
													// NB: No need to do this for Large FAT32, as this only applies to NTFS
	static_strcpy(path, VolumeName);
	static_strcat(path, "EFI\\Rufus\\ntfs_x64.efi");
	if (PathFileExistsA(path)) {
		printf("Windows selected the UEFI:NTFS partition for formatting - Retry needed\n", VolumeName);
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_RETRY;
		goto out;
	}

	// LoadLibrary("fmifs.dll") appears to changes the locale, which can lead to
	// problems with tolower(). Make sure we restore the locale. For more details,
	// see http://comments.gmane.org/gmane.comp.gnu.mingw.user/39300
	locale = setlocale(LC_ALL, NULL);

	setlocale(LC_ALL, locale);

	// Again, skip the RIGHT_TO_LEFT_EMBEDDING mark if present
	index = (wFSType[0] == 0x202b) ? 1 : 0;
	// We may have a " (Default)" trail
	for (i = 0; i < wcslen(wFSType); i++) {
		if (wFSType[i] == ' ') {
			wFSType[i] = 0;
			break;
		}
	}

	ulClusterSize = (ULONG)4096;
	if (ulClusterSize < 0x200) {
		// 0 is FormatEx's value for default, which we need to use for UDF
		ulClusterSize = 0;
		printf("Using default cluster size\n");
	}
	else {
		printf("Using cluster size: %d bytes\n", ulClusterSize);
	}


	pfFormatEx(wVolumeName, SelectedDrive.MediaType, &wFSType[index], wLabel,
		TRUE, ulClusterSize, FormatExCallback);


	if (!IS_ERROR(FormatStatus)) {
		printf("Format completed.\n");
		r = TRUE;
	}

out:
	safe_free(VolumeName);
	safe_free(wVolumeName);
	return r;
}



static BOOL WriteMBR(HANDLE hPhysicalDrive)
{
	BOOL r = FALSE;
	DWORD size;
	unsigned char* buffer = NULL;
	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;
	const char* using_msg = "Using %s MBR\n";

	AnalyzeMBR(hPhysicalDrive, "Drive");

	if (SelectedDrive.SectorSize < 512)
		goto out;

	// FormatEx rewrites the MBR and removes the LBA attribute of FAT16
	// and FAT32 partitions - we need to correct this in the MBR
	buffer = (unsigned char*)_mm_malloc(SelectedDrive.SectorSize, 16);
	if (buffer == NULL) {
		printf("Could not allocate memory for MBR\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	if (!read_sectors(hPhysicalDrive, SelectedDrive.SectorSize, 0, 1, buffer)) {
		printf("Could not read MBR\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_READ_FAULT;
		goto out;
	}


	if (!write_sectors(hPhysicalDrive, SelectedDrive.SectorSize, 0, 1, buffer)) {
		printf("Could not write MBR\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_WRITE_FAULT;
		goto out;
	}

	fake_fd._handle = (char*)hPhysicalDrive;
	set_bytes_per_sector(SelectedDrive.SectorSize);


	// If everything else failed, fall back to a conventional Windows/Rufus MBR
windows_mbr:

	r = write_win7_mbr(fp);


notify:
	// Tell the system we've updated the disk properties
	if (!DeviceIoControl(hPhysicalDrive, IOCTL_DISK_UPDATE_PROPERTIES, NULL, 0, NULL, 0, &size, NULL))

out:
	safe_mm_free(buffer);
	return r;
}



/*
* Write Secondary Boot Record (usually right after the MBR)
*/
static BOOL WriteSBR(HANDLE hPhysicalDrive)
{
	// TODO: Do we need anything special for 4K sectors?
	DWORD size, max_size, mbr_size = 0x200;
	int r, sub_type = bt;
	unsigned char* buf = NULL;
	FAKE_FD fake_fd = { 0 };
	FILE* fp = (FILE*)&fake_fd;

	fake_fd._handle = (char*)hPhysicalDrive;
	set_bytes_per_sector(SelectedDrive.SectorSize);
	// Ensure that we have sufficient space for the SBR
	max_size = 1 * MB;
	max_size -= mbr_size;

	switch (sub_type) {
	default:
		// No need to write secondary block
		return TRUE;
	}
}


BOOL MountVolume(char* drive_name, char *drive_guid)
{
	char mounted_guid[52];	// You need at least 51 characters on XP
	char mounted_letter[16] = { 0 };
	DWORD size;

	if (drive_name[0] == '?')
		return FALSE;

	// For fixed disks, Windows may already have remounted the volume, but with a different letter
	// than the one we want. If that's the case, we need to unmount first.
	if ((GetVolumePathNamesForVolumeNameA(drive_guid, mounted_letter, sizeof(mounted_letter), &size))
		&& (size > 1) && (mounted_letter[0] != drive_name[0])) {
		printf("Volume is already mounted, but as %c: instead of %c: - Unmounting...\n", mounted_letter[0], drive_name[0]);
		if (!DeleteVolumeMountPointA(mounted_letter))
		// Also delete the destination mountpoint if needed (Don't care about errors)
		DeleteVolumeMountPointA(drive_name);
		Sleep(200);
	}

	if (!SetVolumeMountPointA(drive_name, drive_guid)) {
		// If the OS was faster than us at remounting the drive, this operation can fail
		// with ERROR_DIR_NOT_EMPTY. If that's the case, just check that mountpoints match
		if (GetLastError() == ERROR_DIR_NOT_EMPTY) {
			if (!GetVolumeNameForVolumeMountPointA(drive_name, mounted_guid, sizeof(mounted_guid))) {
				return FALSE;
			}
			if (safe_strcmp(drive_guid, mounted_guid) != 0) {
				printf("%s already mounted, but volume GUID doesn't match:\r\n  expected %s, got %s\n",
					drive_name, drive_guid, mounted_guid);
				return FALSE;
			}
			printf("%s was already mounted as %s\n", drive_guid, drive_name);
		}
		else {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL FlushDrive(char drive_letter)
{
	HANDLE hDrive = INVALID_HANDLE_VALUE;
	BOOL r = FALSE;
	char logical_drive[] = "\\\\.\\#:";

	logical_drive[4] = drive_letter;
	hDrive = CreateFileA(logical_drive, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDrive == INVALID_HANDLE_VALUE) {
		goto out;
	}
	r = FlushFileBuffers(hDrive);
	if (r == FALSE)

out:
	safe_closehandle(hDrive);
	return r;
}


BOOL RemountVolume(char* drive_name)
{
	char drive_guid[51];

	// UDF requires a sync/flush, and it's also a good idea for other FS's
	FlushDrive(drive_name[0]);
	if (GetVolumeNameForVolumeMountPointA(drive_name, drive_guid, sizeof(drive_guid))) {
		if (DeleteVolumeMountPointA(drive_name)) {
			Sleep(200);
			if (MountVolume(drive_name, drive_guid)) {
				printf("Successfully remounted %s on %C:\n", drive_guid, drive_name[0]);
			}
			else {
				printf("Failed to remount %s on %C:\n", drive_guid, drive_name[0]);
				// This will leave the drive inaccessible and must be flagged as an error
				FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE);
				return FALSE;
			}
		}
		else {
			// Try to continue regardless
		}
	}
	return TRUE;
}

#pragma pack(1)
typedef struct _FILEDISK_VERIFY_					//磁盘开始的512字节用于校验是否被改动
{
	BYTE				code[500];
	ULONGLONG			diskSize;
	ULONG32				verifyCode;
}FILEDISK_VERIFY, *PFILEDISK_VERIFY;

static const ULONG32 crc32tab[] = {
	0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
	0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
	0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
	0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
	0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
	0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
	0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
	0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
	0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
	0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
	0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
	0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
	0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
	0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
	0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
	0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
	0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
	0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
	0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
	0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
	0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
	0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
	0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
	0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
	0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
	0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
	0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
	0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
	0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
	0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
	0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
	0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
	0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
	0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
	0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
	0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
	0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
	0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
	0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
	0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
	0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
	0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
	0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
	0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
	0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
	0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
	0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
	0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
	0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
	0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
	0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
	0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
	0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
	0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
	0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
	0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
	0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
	0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
	0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
	0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
	0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
	0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
	0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
	0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};
ULONG32 crc32(const unsigned char *buf, ULONG32 size)
{
	ULONG32 i, crc;
	crc = 0xFFFFFFFF;
	for (i = 0; i < size; i++)
		crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
	return crc ^ 0xFFFFFFFF;
}


//这里添加一个扇区的验证数据  chengheming
BOOL WriteModifySector(HANDLE hPhysicalDrive)
{
	BOOL r = FALSE;
	int i;
	unsigned char* bufferSec = NULL;
	DWORD verifyCode;
	PFILEDISK_VERIFY filedisk_verify;

	AnalyzeMBR(hPhysicalDrive, "Drive");

	if (SelectedDrive.SectorSize < 512)
		goto out;

	// FormatEx rewrites the MBR and removes the LBA attribute of FAT16
	// and FAT32 partitions - we need to correct this in the MBR
	bufferSec = (unsigned char*)_mm_malloc(SelectedDrive.SectorSize, 16);
	if (bufferSec == NULL) {
		printf("Could not allocate memory for ModifySector\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NOT_ENOUGH_MEMORY;
		goto out;
	}

	for (i = 0; i < SelectedDrive.SectorSize - 4; i++)
	{
		bufferSec[i] = rand() / 0xFF;
	}

	filedisk_verify = (PFILEDISK_VERIFY)bufferSec;
	filedisk_verify->diskSize = SelectedDrive.DiskSize;				//把u盘的大小直接写到记录里

	verifyCode = crc32(bufferSec, 508);

	filedisk_verify->verifyCode = verifyCode;


	//2048 + 20480这里是写验证数据的扇区偏移
	if (!write_sectors(hPhysicalDrive, SelectedDrive.SectorSize, 22528, 1, bufferSec)) {
		printf("Could not write MBR\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_WRITE_FAULT;
		goto out;
	}

	safe_mm_free(bufferSec);
	return TRUE;
out:
	safe_mm_free(bufferSec);
	return r;
}


//格式化线程  传进来的是物理磁盘号
DWORD WINAPI FormatThread(void* param)
{
	int i, r;
	BOOL ret, use_large_fat32, windows_to_go;
	DWORD DriveIndex = (DWORD)(uintptr_t)param;
	HANDLE hPhysicalDrive = INVALID_HANDLE_VALUE;
	HANDLE hLogicalVolume = INVALID_HANDLE_VALUE;
	HANDLE hSourceImage = INVALID_HANDLE_VALUE;
	SYSTEMTIME lt;
	FILE* log_fd;
	uint8_t *buffer = NULL, extra_partitions = 0;
	char *bb_msg, *guid_volume = NULL;
	char drive_name[] = "?:\\";
	char drive_letters[27], fs_type[32];
	char logfile[MAX_PATH], *userdir;
	char efi_dst[] = "?:\\efi\\boot\\bootx64.efi";
	char kolibri_dst[] = "?:\\MTLD_F32";
	char grub4dos_dst[] = "?:\\grldr";

	use_large_fat32 = 0;
	windows_to_go = 0;
	large_drive = (SelectedDrive.DiskSize > (1 * TB));
	if (large_drive)
		printf("Notice: Large drive detected (may produce short writes)\n");

	hPhysicalDrive = GetPhysicalHandle(DriveIndex, lock_drive, TRUE, !lock_drive);
	if (hPhysicalDrive == INVALID_HANDLE_VALUE) {
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_OPEN_FAILED;
		goto out;
	}

	// At this stage we should have both a handle and a lock to the physical drive...
	if (!GetDriveLetters(DriveIndex, drive_letters)) {
		printf("Failed to get a drive letter\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | APPERR(ERROR_CANT_ASSIGN_LETTER);
		goto out;
	}
	if (drive_letters[0] == 0) {
		printf("No drive letter was assigned...\n");
		drive_name[0] = GetUnusedDriveLetter();
		if (drive_name[0] == 0) {
			printf("Could not find a suitable drive letter\n");
			FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | APPERR(ERROR_CANT_ASSIGN_LETTER);
			goto out;
		}
	}
	else {
		// Unmount all mounted volumes that belong to this drive
		// Do it in reverse so that we always end on the first volume letter
		for (i = (int)safe_strlen(drive_letters); i > 0; i--) {
			drive_name[0] = drive_letters[i - 1];

			if (!DeleteVolumeMountPointA(drive_name)) {
				// Try to continue. We will bail out if this causes an issue.
			}
		}
	}
	printf("Will use '%c:' as volume mountpoint\n", drive_name[0]);

	// ...but we need a lock to the logical drive to be able to write anything to it
	hLogicalVolume = GetLogicalHandle(DriveIndex, TRUE, FALSE, !lock_drive);
	if (hLogicalVolume == INVALID_HANDLE_VALUE) {
		printf("Could not lock volume\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_OPEN_FAILED;
		goto out;
	}
	else if (hLogicalVolume == NULL) {
		// NULL is returned for cases where the drive is not yet partitioned
		printf("Drive does not appear to be partitioned\n");
	}
	else if (!UnmountVolume(hLogicalVolume)) {
		printf("Trying to continue regardless...\n");
	}

 	AnalyzeMBR(hPhysicalDrive, "Drive");
	if ((hLogicalVolume != NULL) && (hLogicalVolume != INVALID_HANDLE_VALUE)) {
		AnalyzePBR(hLogicalVolume);
	}

	// Zap any existing partitions. This helps prevent access errors.
	// Note, Microsoft's way of cleaning partitions (IOCTL_DISK_CREATE_DISK, which is what we apply
	// in InitializeDisk) is *NOT ENOUGH* to reset a disk and can render it inoperable for partitioning
	// or formatting under Windows. See https://github.com/pbatard/rufus/issues/759 for details.

	if ((!ClearMBRGPT(hPhysicalDrive, SelectedDrive.DiskSize, SelectedDrive.SectorSize, use_large_fat32)) ||
		(!InitializeDisk(hPhysicalDrive))) {
		printf("Could not reset partitions\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_PARTITION_FAILURE;
		goto out;
	}
	


	if (!CreatePartition(hPhysicalDrive, pt, fs, 0, extra_partitions)) {
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_PARTITION_FAILURE;
		goto out;
	}

	if (!usualFormat)
	{
		if (!WriteModifySector(hPhysicalDrive))
		{
			FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_PARTITION_FAILURE;
			goto out;
		}
	}


	// Close the (unmounted) volume before formatting
	if ((hLogicalVolume != NULL) && (hLogicalVolume != INVALID_HANDLE_VALUE)) {
		if (!CloseHandle(hLogicalVolume)) {
			FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_ACCESS_DENIED;
			goto out;
		}
	}
	hLogicalVolume = INVALID_HANDLE_VALUE;

	// Wait for the logical drive we just created to appear
	printf("Waiting for logical drive to reappear...\n");
	Sleep(200);
	if (!WaitForLogical(DriveIndex))
		printf("Logical drive was not found!\n");	// We try to continue even if this fails, just in case


	// If FAT32 is requested and we have a large drive (>32 GB) use
	// large FAT32 format, else use MS's FormatEx.
	ret = FormatDrive(DriveIndex);
	if (!ret) {
		// Error will be set by FormatDrive() in FormatStatus
		goto out;
	}

	// Thanks to Microsoft, we must fix the MBR AFTER the drive has been formatted
	if (pt == PARTITION_STYLE_MBR) {
		if ((!WriteMBR(hPhysicalDrive)) || (!WriteSBR(hPhysicalDrive))) {
			if (!IS_ERROR(FormatStatus))
				FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_WRITE_FAULT;
			goto out;
		}

	}
	Sleep(200);
	WaitForLogical(DriveIndex);
	// Try to continue


	guid_volume = GetLogicalName(DriveIndex, TRUE, TRUE);
	if (guid_volume == NULL) {
		printf("Could not get GUID volume name\n");
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | ERROR_NO_VOLUME_ID;
		goto out;
	}
	printf("Found volume GUID %s\n", guid_volume);

	if (!MountVolume(drive_name, guid_volume)) {
		FormatStatus = ERROR_SEVERITY_ERROR | FAC(FACILITY_STORAGE) | APPERR(ERROR_CANT_MOUNT_VOLUME);
		goto out;
	}

	// Disable file indexing, unless it was force-enabled by the user

		printf("Disabling file indexing...\n");
		if (!SetFileAttributesA(guid_volume, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED))


	// Refresh the drive label - This is needed as Windows may have altered it from
	// the name we proposed, and we require an exact label, to patch config files.
// 	if (!GetVolumeInformationU(drive_name, img_report.usb_label, ARRAYSIZE(img_report.usb_label),
// 		NULL, NULL, NULL, NULL, 0)) {
// 	}


	// We issue a complete remount of the filesystem at on account of:
	// - Ensuring the file explorer properly detects that the volume was updated
	// - Ensuring that an NTFS system will be reparsed so that it becomes bootable
	if (!RemountVolume(drive_name))
		goto out;

out:
// 	zero_drive = FALSE;
	safe_free(guid_volume);
	safe_free(buffer);
	safe_closehandle(hSourceImage);
	safe_unlockclose(hLogicalVolume);
	safe_unlockclose(hPhysicalDrive);	// This can take a while
	if (IS_ERROR(FormatStatus)) {
		guid_volume = GetLogicalName(DriveIndex, TRUE, FALSE);
		if (guid_volume != NULL) {
// 			if (MountVolume(drive_name, guid_volume))
// 				printf("Re-mounted volume as '%c:' after error\n", drive_name[0]);
			free(guid_volume);
		}
	}

	return FormatStatus;
}



int main(int argc, char** argv)
{
	if (argc != 3)
	{
		printf("argc error!\n");
		return -1;
	}

	DWORD phyNum;
	phyNum = atoi((char *)argv[1]);
	usualFormat = atoi((char *)argv[2]);
	

	char FileSystemName[32];
	if (!GetDrivePartitionData(phyNum, FileSystemName, sizeof(FileSystemName), FALSE))
	{
		return 1;			//获取磁盘信息失败
	}
	DWORD errCode = FormatThread((void *)phyNum);

	printf("errCode: %08x\n", errCode);

	return errCode;
}
