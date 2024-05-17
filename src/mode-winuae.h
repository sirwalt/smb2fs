
#define UAEFSDB_LEN 604
#define UAEFSDB2_LEN 1632

struct uaefsdb 
{
    u_int8_t valid;
    u_int32_t protection_bits;
    u_int32_t windows_mode;
    char* aname;
    char* nname;
    char* comment;
};

uint32_t uaefsdb_set_smb_modeattributes(uint32_t protection_bits, uint32_t *smb2_raw_file_attributes);

int uaefsdb_deserialize(u_int8_t* buffer,size_t buffer_size, struct uaefsdb* fsdb);

void uaefsdb_set_protection_bits(uint32_t protection_bits, uint32_t smb2_raw_file_attributes, u_int8_t* fsdb_buffer,size_t fsdb_buffer_size);
uint32_t uaefsdb_get_protection_bits(uint32_t smb2_raw_file_attributes, u_int8_t* fsdb_buffer,size_t fsdb_buffer_size);

int uaefsdb_get_comment(u_int8_t* fsdb_buffer,size_t fsdb_buffer_size, APTR comment_buf, size_t len);
void uaefsdb_set_comment(u_int8_t* fsdb_buffer,size_t fsdb_buffer_size, APTR comment_buf, size_t len);