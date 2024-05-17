#define __USE_INLINE__

#include <stdint.h>
#ifndef __amigaos4__
#include <clib/debug_protos.h>
#endif

#include <dos/filehandler.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef __amigaos4__
#include <unistd.h>
#else
#include <sys/param.h>
#endif

#include "mode-winuae.h"


int uaefsdb_serialize(u_int8_t* buffer,size_t buffer_size, struct uaefsdb* fsdb)
{
    if(buffer_size != UAEFSDB_LEN && buffer_size != UAEFSDB2_LEN)
        return -EINVAL;

    if(fsdb == NULL || buffer == NULL)
        return -EINVAL;
    
    
    *(uint8_t*)buffer = 1;

    buffer+=1;
    *(uint32_t*)buffer = fsdb->protection_bits;

    buffer+=4+257+257+81;
    *(uint32_t*)buffer = fsdb->windows_mode;

    return 0;
}

int uaefsdb_deserialize(u_int8_t* buffer,size_t buffer_size, struct uaefsdb* fsdb)
{
    // char buffer_x[UAEFSDB_LEN + 1];
    
    if(buffer_size != UAEFSDB_LEN && buffer_size != UAEFSDB2_LEN)
        return -EINVAL;

    if(fsdb == NULL || buffer == NULL)
        return -EINVAL;
    
    // memcpy(buffer_x, buffer, UAEFSDB_LEN);
    // for (int i = 0; i < UAEFSDB_LEN; ++i)
    // {
    //     if(buffer_x[i] == 0) buffer_x[i] = '0';
    // }

    // buffer_x[UAEFSDB_LEN] = 0;
    // KPrintF((STRPTR)"[smb2fs] Buffer AS:%s\n",buffer_x);
    
    buffer+=1;
    fsdb->protection_bits = *(uint32_t*)buffer;

    buffer+=4;
    fsdb->aname = *buffer == '\0' ? NULL : (char*) buffer;

    buffer+=257;
    fsdb->nname = *buffer == '\0' ? NULL : (char*) buffer;

    buffer+=257;
    fsdb->comment = *buffer == '\0' ? NULL : (char*) buffer;
 
    buffer+=81;
    fsdb->windows_mode = *(uint32_t*)buffer;

    return 0;
}

// Constants are actually same as the SMB Constant
// Still working with those for brevity
#define FILE_ATTRIBUTE_READONLY 0x00000001
#define FILE_ATTRIBUTE_HIDDEN 0x00000002
#define FILE_ATTRIBUTE_SYSTEM 0x00000004
#define FILE_ATTRIBUTE_ARCHIVE 0x00000020
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_ATTRIBUTES_GETMASK (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN) 
#define FILE_ATTRIBUTES_SETMASK (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL) 


#define SMB_TO_WINMODE(smb2_raw_file_attributes) (FILE_ATTRIBUTES_GETMASK & smb2_raw_file_attributes)

uint32_t uaefsdb_set_smb_modeattributes(uint32_t protection_bits, uint32_t *smb2_raw_file_attributes)
{
    uint32_t attributes = 0;

    if(!(protection_bits & FIBF_ARCHIVE))
        attributes |= FILE_ATTRIBUTE_ARCHIVE;

    if((protection_bits & FIBF_WRITE) && (protection_bits & FIBF_DELETE))
        attributes |= FILE_ATTRIBUTE_READONLY;

    if(protection_bits & FIBF_HOLD)
        attributes |= FILE_ATTRIBUTE_HIDDEN;

    if(protection_bits & FIBF_PURE)
        attributes |= FILE_ATTRIBUTE_SYSTEM;

    if(attributes == 0)
        attributes = FILE_ATTRIBUTE_NORMAL;

    *smb2_raw_file_attributes &= (~FILE_ATTRIBUTES_SETMASK);
    *smb2_raw_file_attributes |= attributes;

    return *smb2_raw_file_attributes;
}

void uaefsdb_set_protection_bits(uint32_t protection_bits, uint32_t smb2_raw_file_attributes, u_int8_t* fsdb_buffer,size_t fsdb_buffer_size)
{
    struct uaefsdb  fsdb;
    int             rc;

    memset(&fsdb, 0, sizeof(struct uaefsdb));

    rc = uaefsdb_deserialize(fsdb_buffer, fsdb_buffer_size, &fsdb);

    if(rc == 0)
    {
        fsdb.windows_mode = smb2_raw_file_attributes;
        fsdb.protection_bits = protection_bits;
    }

    uaefsdb_serialize(fsdb_buffer, fsdb_buffer_size, &fsdb);
}

uint32_t uaefsdb_get_protection_bits(uint32_t smb2_raw_file_attributes, u_int8_t* fsdb_buffer,size_t fsdb_buffer_size)
{
    uint32_t protection_bits = 0;
    struct uaefsdb  fsdb;
    int             rc;
    uint32_t        windows_mode = SMB_TO_WINMODE(smb2_raw_file_attributes);

    memset(&fsdb, 0, sizeof(struct uaefsdb));

    rc = uaefsdb_deserialize(fsdb_buffer, fsdb_buffer_size, &fsdb);

    if(rc == 0 && (windows_mode == SMB_TO_WINMODE(fsdb.windows_mode)))
    {
        // we can use protection bits from fsdb
        protection_bits = fsdb.protection_bits;
        // KPrintF((STRPTR)"[smb2fs] Protection Bits (no change):%ld\n",fsdb.protection_bits);
    }
    else
    {
        // if(rc == 0)
        // {
        //     KPrintF((STRPTR)"[smb2fs] Winmode SMB:%ld\n",windows_mode);
        //     KPrintF((STRPTR)"[smb2fs] Winmode AS:%ld\n",fsdb.windows_mode);
        // }

        if(!(windows_mode & FILE_ATTRIBUTE_ARCHIVE))
            protection_bits |= FIBF_ARCHIVE;

        if(windows_mode & FILE_ATTRIBUTE_READONLY)
            protection_bits |= (FIBF_WRITE | FIBF_DELETE);

        if(windows_mode & FILE_ATTRIBUTE_HIDDEN)
            protection_bits |= FIBF_HOLD;

        if(windows_mode & FILE_ATTRIBUTE_SYSTEM)
            protection_bits |= FIBF_PURE;

        // KPrintF((STRPTR)"[smb2fs] Protection Bits (change):%ld\n",fsdb.protection_bits);
    }

    return protection_bits;
}

int uaefsdb_get_comment(u_int8_t* fsdb_buffer,size_t fsdb_buffer_size, APTR comment_buf, size_t len)
{
    struct uaefsdb  fsdb;
    int             rc;

    memset(&fsdb, 0, sizeof(struct uaefsdb));

    rc = uaefsdb_deserialize(fsdb_buffer, fsdb_buffer_size, &fsdb);

    if(rc == 0 && fsdb.comment != NULL)
    {
        strncpy(comment_buf, fsdb.comment, len);
        return strlen(comment_buf);
    }

    return -ENODATA;
}

void uaefsdb_set_comment(u_int8_t* fsdb_buffer,size_t fsdb_buffer_size, APTR comment_buf, size_t len)
{
    struct uaefsdb  fsdb;
    int             rc;

    memset(&fsdb, 0, sizeof(struct uaefsdb));

    rc = uaefsdb_deserialize(fsdb_buffer, fsdb_buffer_size, &fsdb);

    if(rc == 0)
    {
        memset(fsdb_buffer+1+4+257+257, 0, 81);

        // Well very bad, but this entire file needs refactoring
        strncpy(fsdb_buffer+1+4+257+257, comment_buf, MIN(len, 80));
    }

    uaefsdb_serialize(fsdb_buffer, fsdb_buffer_size, &fsdb);
}