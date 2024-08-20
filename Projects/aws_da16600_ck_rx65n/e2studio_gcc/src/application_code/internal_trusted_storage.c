#include "psa/internal_trusted_storage.h"

#include <stdio.h>
#include "lfs.h"
#include "common.h"

#if !defined(PSA_ITS_STORAGE_PREFIX)
#define PSA_ITS_STORAGE_PREFIX ""
#endif

#define PSA_ITS_STORAGE_FILENAME_PATTERN "%08x%08x"
#define PSA_ITS_STORAGE_SUFFIX ".psa_its"
#define PSA_ITS_STORAGE_FILENAME_LENGTH         \
    ( sizeof( PSA_ITS_STORAGE_PREFIX ) - 1 + /*prefix without terminating 0*/ \
      16 + /*UID (64-bit number in hex)*/                               \
      sizeof( PSA_ITS_STORAGE_SUFFIX ) - 1 + /*suffix without terminating 0*/ \
      1 /*terminating null byte*/ )
#define PSA_ITS_STORAGE_TEMP \
    PSA_ITS_STORAGE_PREFIX "tempfile" PSA_ITS_STORAGE_SUFFIX

#define PSA_ITS_MAGIC_STRING "PSA\0ITS\0"
#define PSA_ITS_MAGIC_LENGTH 8

typedef struct
{
    uint8_t magic[PSA_ITS_MAGIC_LENGTH];
    uint8_t size[sizeof( uint32_t )];
    uint8_t flags[sizeof( psa_storage_create_flags_t )];
} psa_its_file_header_t;

extern lfs_t g_rm_littlefs0_lfs;

static void psa_its_fill_filename( psa_storage_uid_t uid, char *filename )
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    snprintf( filename, PSA_ITS_STORAGE_FILENAME_LENGTH,
                      "%s" PSA_ITS_STORAGE_FILENAME_PATTERN "%s",
                      PSA_ITS_STORAGE_PREFIX,
                      (unsigned) ( uid >> 32 ),
                      (unsigned) ( uid & 0xffffffff ),
                      PSA_ITS_STORAGE_SUFFIX );
}

static psa_status_t psa_its_read_file( psa_storage_uid_t uid,
                                       struct psa_storage_info_t *p_info,
                                       lfs_file_t* file )
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    psa_its_file_header_t header;
    lfs_ssize_t n;

    psa_its_fill_filename( uid, filename );
    if (lfs_file_open(&g_rm_littlefs0_lfs, file, filename, LFS_O_RDONLY) < 0)
        return( PSA_ERROR_DOES_NOT_EXIST );

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
//    mbedtls_setbuf( *p_stream, NULL );

    n = lfs_file_read(&g_rm_littlefs0_lfs, file, &header, sizeof (header));
    if( n != sizeof( header ) )
        return( PSA_ERROR_DATA_CORRUPT );
    if( memcmp( header.magic, PSA_ITS_MAGIC_STRING,
                PSA_ITS_MAGIC_LENGTH ) != 0 )
        return( PSA_ERROR_DATA_CORRUPT );

    p_info->size = ( header.size[0] |
                     header.size[1] << 8 |
                     header.size[2] << 16 |
                     header.size[3] << 24 );
    p_info->flags = ( header.flags[0] |
                      header.flags[1] << 8 |
                      header.flags[2] << 16 |
                      header.flags[3] << 24 );
    return( PSA_SUCCESS );
}

psa_status_t psa_its_get_info( psa_storage_uid_t uid,
                               struct psa_storage_info_t *p_info )
{
    psa_status_t status;
    lfs_file_t file;
    status = psa_its_read_file( uid, p_info, &file );
    if (status == PSA_SUCCESS)
    	lfs_file_close(&g_rm_littlefs0_lfs, &file);

    return( status );
}

psa_status_t psa_its_get( psa_storage_uid_t uid,
                          uint32_t data_offset,
                          uint32_t data_length,
                          void *p_data,
                          size_t *p_data_length )
{
    psa_status_t status;
    lfs_file_t file;
    lfs_ssize_t n;
    struct psa_storage_info_t info;
    int opened = 0;

    status = psa_its_read_file( uid, &info, &file );
    if( status != PSA_SUCCESS )
        goto exit;
    opened = 1;
    status = PSA_ERROR_INVALID_ARGUMENT;
    if( data_offset + data_length < data_offset )
        goto exit;
    if( data_offset + data_length > info.size )
        goto exit;

    status = PSA_ERROR_STORAGE_FAILURE;
    while( data_offset > LONG_MAX )
    {
        if( lfs_file_seek(&g_rm_littlefs0_lfs, &file, LONG_MAX, LFS_SEEK_CUR) < 0 )
            goto exit;
        data_offset -= LONG_MAX;
    }
    if( lfs_file_seek(&g_rm_littlefs0_lfs, &file, data_offset, LFS_SEEK_CUR) < 0 )
        goto exit;
    n = lfs_file_read(&g_rm_littlefs0_lfs, &file, p_data, data_length);
    if( n != data_length )
        goto exit;
    status = PSA_SUCCESS;
    if( p_data_length != NULL )
        *p_data_length = n;

exit:
    if( opened )
        lfs_file_close(&g_rm_littlefs0_lfs, &file);
    return( status );
}

psa_status_t psa_its_set( psa_storage_uid_t uid,
                          uint32_t data_length,
                          const void *p_data,
                          psa_storage_create_flags_t create_flags )
{
    if( uid == 0 )
    {
        return( PSA_ERROR_INVALID_HANDLE );
    }

    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    lfs_file_t file;
    psa_its_file_header_t header;
    lfs_ssize_t n;
    int opened = 0;

    memcpy( header.magic, PSA_ITS_MAGIC_STRING, PSA_ITS_MAGIC_LENGTH );
    MBEDTLS_PUT_UINT32_LE( data_length, header.size, 0 );
    MBEDTLS_PUT_UINT32_LE( create_flags, header.flags, 0 );

    psa_its_fill_filename( uid, filename );
    if (lfs_file_open(&g_rm_littlefs0_lfs, &file, PSA_ITS_STORAGE_TEMP, LFS_O_WRONLY | LFS_O_CREAT) < 0)
    	goto exit;
    opened = 1;

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    //mbedtls_setbuf( stream, NULL );

    status = PSA_ERROR_INSUFFICIENT_STORAGE;
    n = lfs_file_write(&g_rm_littlefs0_lfs, &file, &header, sizeof(header));
    if( n != sizeof( header ) )
        goto exit;
    if( data_length != 0 )
    {
        n = lfs_file_write(&g_rm_littlefs0_lfs, &file, p_data, data_length);
        if( n != data_length )
            goto exit;
    }
    status = PSA_SUCCESS;

exit:
    if(opened)
    {
    	int ret = lfs_file_close(&g_rm_littlefs0_lfs, &file);
        if( status == PSA_SUCCESS && ret < 0 )
            status = PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    if( status == PSA_SUCCESS )
    {
    	if (lfs_rename(&g_rm_littlefs0_lfs, PSA_ITS_STORAGE_TEMP, filename) < 0)
            status = PSA_ERROR_STORAGE_FAILURE;
    }
    /* The temporary file may still exist, but only in failure cases where
     * we're already reporting an error. So there's nothing we can do on
     * failure. If the function succeeded, and in some error cases, the
     * temporary file doesn't exist and so remove() is expected to fail.
     * Thus we just ignore the return status of remove(). */
    lfs_remove(&g_rm_littlefs0_lfs, PSA_ITS_STORAGE_TEMP);
    return( status );
}

psa_status_t psa_its_remove( psa_storage_uid_t uid )
{
    char filename[PSA_ITS_STORAGE_FILENAME_LENGTH];
    lfs_file_t file;
    psa_its_fill_filename( uid, filename );
    if (lfs_file_open(&g_rm_littlefs0_lfs, &file, filename, LFS_O_RDONLY) < 0)
        return( PSA_ERROR_DOES_NOT_EXIST );
    lfs_file_close(&g_rm_littlefs0_lfs, &file);
    if(lfs_remove(&g_rm_littlefs0_lfs, filename) < 0)
        return( PSA_ERROR_STORAGE_FAILURE );
    return( PSA_SUCCESS );
}
