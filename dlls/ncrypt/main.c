/*
 * New cryptographic library (ncrypt.dll)
 *
 * Copyright 2016 Alex Henrie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "ncrypt.h"
#include "bcrypt.h"
#include "ncrypt_internal.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ncrypt);

static SECURITY_STATUS map_ntstatus(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_INVALID_HANDLE:    return NTE_INVALID_HANDLE;
    case STATUS_INVALID_SIGNATURE: return NTE_BAD_SIGNATURE;
    case STATUS_SUCCESS:           return ERROR_SUCCESS;
    case STATUS_INVALID_PARAMETER: return NTE_INVALID_PARAMETER;
    case STATUS_NO_MEMORY:         return NTE_NO_MEMORY;
    case STATUS_NOT_SUPPORTED:     return NTE_NOT_SUPPORTED;
    case NTE_BAD_DATA:             return NTE_BAD_DATA;
    case STATUS_BUFFER_TOO_SMALL:  return NTE_BUFFER_TOO_SMALL;
    default:
        FIXME("unhandled status %#lx\n", status);
        return NTE_INTERNAL_ERROR;
    }
}

static struct object *allocate_object(enum object_type type)
{
    struct object *ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->type = type;
    ret->refs = 1;
    return ret;
}

static void provider_addref(NCRYPT_PROV_HANDLE handle)
{
    struct object *object = (struct object *)handle;
    InterlockedIncrement(&object->refs);
}

static struct object_property *get_object_property(struct object *object, const WCHAR *name)
{
    unsigned int i;
    for (i = 0; i < object->num_properties; i++)
    {
        struct object_property *property = &object->properties[i];
        if (property->key && !lstrcmpW(property->key, name)) return property;
    }
    return NULL;
}

struct object_property *add_object_property(struct object *object, const WCHAR *name)
{
    struct object_property *property;

    if (!object->num_properties)
    {
        if (!(object->properties = malloc(sizeof(*property))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        property = &object->properties[object->num_properties++];
    }
    else
    {
        struct object_property *tmp;
        if (!(tmp = realloc(object->properties, sizeof(*property) * (object->num_properties + 1))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        object->properties = tmp;
        property = &object->properties[object->num_properties++];
    }

    memset(property, 0, sizeof(*property));
    if (!(property->key = wcsdup(name)))
    {
        ERR("Error allocating memory.\n");
        return NULL;
    }

    return property;
}

static SECURITY_STATUS set_object_property(struct object *object, const WCHAR *name, BYTE *value, DWORD value_size)
{
    struct object_property *property = get_object_property(object, name);
    void *tmp;

    if (!property && !(property = add_object_property(object, name))) return NTE_NO_MEMORY;

    property->value_size = value_size;
    if (!(tmp = realloc(property->value, value_size)))
    {
        ERR("Error allocating memory.\n");
        free(property->key);
        property->key = NULL;
        return NTE_NO_MEMORY;
    }

    property->value = tmp;
    memcpy(property->value, value, value_size);

    return ERROR_SUCCESS;
}

static void free_object(struct object *object);

static struct object *create_key_object(enum algid algid, NCRYPT_PROV_HANDLE provider)
{
    NCRYPT_SUPPORTED_LENGTHS supported_lengths = {512, 16384, 8, 1024};
    DWORD block_length = 128, signature_length = 128, export_policy = 0, usage = NCRYPT_ALLOW_ALL_USAGES, key_type = 0;
    struct object *object;
    SECURITY_STATUS ret;

    if (algid != RSA && algid != ECDSA_P256)
    {
        ERR("Invalid algid %#x\n", algid);
        return NULL;
    }
    if (!(object = allocate_object(KEY))) return NULL;
    object->key.algid = algid;

    if (algid == RSA)
    {
        if ((ret = set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)BCRYPT_RSA_ALGORITHM,
                                       sizeof(BCRYPT_RSA_ALGORITHM)))) goto fail;
        if ((ret = set_object_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, (BYTE *)BCRYPT_RSA_ALGORITHM,
                                       sizeof(BCRYPT_RSA_ALGORITHM)))) goto fail;
        if ((ret = set_object_property(object, NCRYPT_LENGTHS_PROPERTY, (BYTE *)&supported_lengths,
                                       sizeof(supported_lengths)))) goto fail;
        if ((ret = set_object_property(object, NCRYPT_BLOCK_LENGTH_PROPERTY, (BYTE *)&block_length,
                                       sizeof(block_length)))) goto fail;
        if ((ret = set_object_property(object, BCRYPT_SIGNATURE_LENGTH, (BYTE *)&signature_length,
                                       sizeof(signature_length)))) goto fail;
    }
    else
    {
        if ((ret = set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)BCRYPT_ECDSA_P256_ALGORITHM,
                                       sizeof(BCRYPT_ECDSA_P256_ALGORITHM)))) goto fail;
        if ((ret = set_object_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, (BYTE *)NCRYPT_ECDSA_ALGORITHM_GROUP,
                                       sizeof(NCRYPT_ECDSA_ALGORITHM_GROUP)))) goto fail;
    }

    if ((ret = set_object_property(object, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE *)&export_policy,
                                   sizeof(export_policy)))) goto fail;
    if ((ret = set_object_property(object, NCRYPT_KEY_USAGE_PROPERTY, (BYTE *)&usage, sizeof(usage)))) goto fail;
    if ((ret = set_object_property(object, NCRYPT_KEY_TYPE_PROPERTY, (BYTE *)&key_type, sizeof(key_type)))) goto fail;
    /* The reference is taken only once the property that free_object releases it through exists. */
    if ((ret = set_object_property(object, NCRYPT_PROVIDER_HANDLE_PROPERTY, (BYTE *)&provider,
                                   sizeof(provider)))) goto fail;
    provider_addref(provider);
    return object;

fail:
    ERR("Error allocating memory\n");
    free_object(object);
    return NULL;
}

/* Releases the properties, and the provider reference a key holds, then the object itself. */
static void free_object(struct object *object)
{
    unsigned int i;

    for (i = 0; i < object->num_properties; i++)
    {
        if (object->properties[i].key && object->properties[i].value &&
            !wcscmp(object->properties[i].key, NCRYPT_PROVIDER_HANDLE_PROPERTY))
            NCryptFreeObject(*(NCRYPT_HANDLE *)object->properties[i].value);

        free(object->properties[i].key);
        free(object->properties[i].value);
    }
    free(object->properties);
    free(object);
}

/* Records the key length on a key whose BCrypt key exists; on failure destroys the whole key. */
static SECURITY_STATUS set_key_length(struct object *object, DWORD bitlen)
{
    SECURITY_STATUS ret;

    if ((ret = set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bitlen, sizeof(bitlen))) ||
        (ret = set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&bitlen, sizeof(bitlen))))
    {
        BCryptDestroyKey(object->key.bcrypt_key);
        free_object(object);
    }
    return ret;
}

SECURITY_STATUS WINAPI NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                                const WCHAR *algid, const WCHAR *name, DWORD keyspec, DWORD flags)
{
    struct object *object;

    TRACE("(%#Ix, %p, %s, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(algid),
          wine_dbgstr_w(name), keyspec, flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (name) FIXME("Persistent keys are not supported\n");

    if (!lstrcmpiW(algid, BCRYPT_RSA_ALGORITHM))
    {
        NTSTATUS status;
        DWORD default_bitlen = 1024;

        if (!(object = create_key_object(RSA, provider)))
        {
            ERR("Error allocating memory\n");
            return NTE_NO_MEMORY;
        }

        status = BCryptGenerateKeyPair(BCRYPT_RSA_ALG_HANDLE, &object->key.bcrypt_key, default_bitlen, 0);
        if (status != STATUS_SUCCESS)
        {
            ERR("Error generating key pair %#lx\n", status);
            free_object(object);
            return map_ntstatus(status);
        }

        if ((status = set_key_length(object, default_bitlen))) return status;
    }
    else if (!lstrcmpiW(algid, BCRYPT_ECDSA_P256_ALGORITHM))
    {
        NTSTATUS status;
        DWORD bitlen = 256;

        if (!(object = create_key_object(ECDSA_P256, provider)))
            return NTE_NO_MEMORY;

        status = BCryptGenerateKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, &object->key.bcrypt_key, bitlen, 0);
        if (status != STATUS_SUCCESS)
        {
            free_object(object);
            return map_ntstatus(status);
        }

        if ((status = set_key_length(object, bitlen))) return status;
    }
    else
    {
        FIXME("Algorithm not handled %s\n", wine_dbgstr_w(algid));
        return NTE_NOT_SUPPORTED;
    }

    *key = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptDecrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    FIXME("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx): stub\n", key, input, insize, padding,
          output, outsize, result, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptDeleteKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    FIXME("(%#Ix, %#lx): stub\n", key, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptEncrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *key_object = (struct object *)key;

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", key, input, insize, padding,
          output, outsize, result, flags);

    if (flags & ~(NCRYPT_NO_PADDING_FLAG | NCRYPT_PAD_OAEP_FLAG
                | NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG))
    {
        FIXME("Flags %lx not supported\n", flags);
        return NTE_BAD_FLAGS;
    }

    if (flags & NCRYPT_NO_PADDING_FLAG || flags & NCRYPT_PAD_OAEP_FLAG)
    {
        FIXME("No padding and oaep padding not supported\n");
        return NTE_NOT_SUPPORTED;
    }

    if (key_object->type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptEncrypt(key_object->key.bcrypt_key, input, insize, padding,
                                      NULL, 0, output, outsize, result, flags));
}

SECURITY_STATUS WINAPI NCryptEnumAlgorithms(NCRYPT_PROV_HANDLE provider, DWORD alg_ops,
                                            DWORD *alg_count, NCryptAlgorithmName **alg_list, DWORD flags)
{
    FIXME("(%#Ix, %#lx, %p, %p, %#lx): stub\n", provider, alg_ops, alg_count, alg_list, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptEnumKeys(NCRYPT_PROV_HANDLE provider, const WCHAR *scope,
                                      NCryptKeyName **key_name, PVOID *enum_state, DWORD flags)
{
    FIXME("(%#Ix, %p, %p, %p, %#lx): stub\n", provider, scope, key_name, enum_state, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE handle, DWORD flags)
{
    struct object *object = (struct object *)handle;
    DWORD key_length;
    struct object_property *prop;
    NTSTATUS status;

    TRACE("(%#Ix, %#lx)\n", handle, flags);

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;

    if (!(prop = get_object_property(object, NCRYPT_LENGTH_PROPERTY))) return NTE_INVALID_HANDLE;
    key_length = *(DWORD *)prop->value;
    status = BCryptSetProperty(object->key.bcrypt_key, BCRYPT_KEY_LENGTH, (UCHAR *)&key_length, sizeof(key_length), 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error setting key length property\n");
        return map_ntstatus(status);
    }

    status = BCryptFinalizeKeyPair(object->key.bcrypt_key, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error finalizing key pair\n");
        return map_ntstatus(status);
    }

    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFreeBuffer(PVOID buf)
{
    FIXME("(%p): stub\n", buf);
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS free_key_object(struct key *key)
{
    return map_ntstatus( BCryptDestroyKey(key->bcrypt_key) );
}

SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE handle)
{
    struct object *object = (struct object *)handle;
    SECURITY_STATUS ret = STATUS_SUCCESS;

    TRACE("(%#Ix)\n", handle);

    if (!object)
    {
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    switch (object->type)
    {
    case KEY:
    {
        if ((ret = free_key_object(&object->key))) return ret;
        break;
    }
    case STORAGE_PROVIDER:
        if (InterlockedDecrement(&object->refs))
            return 0;
        break;

    default:
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    free_object(object);
    return ret;
}

SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *output,
                                         DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *object = (struct object *)handle;
    const struct object_property *property;

    TRACE("(%#Ix, %s, %p, %lu, %p, %#lx)\n", handle, wine_dbgstr_w(name), output, outsize, result, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (!(property = get_object_property(object, name)))
    {
        /* A key from a blob with a P-256 magic has no curve name property on Windows. */
        if (object->type == KEY && object->key.algid == ECDSA_P256 && !wcscmp(name, BCRYPT_ECC_CURVE_NAME))
            return NTE_NOT_FOUND;
        return NTE_INVALID_PARAMETER;
    }

    *result = property->value_size;
    if (!output) return ERROR_SUCCESS;
    if (outsize < property->value_size) return NTE_BUFFER_TOO_SMALL;

    memcpy(output, property->value, property->value_size);
    if (!wcscmp(name, NCRYPT_PROVIDER_HANDLE_PROPERTY))
        provider_addref(*(NCRYPT_PROV_HANDLE*)property->value);
    return ERROR_SUCCESS;
}

/* The named curves CNG knows. */
static const WCHAR *const known_curves[] =
{
    L"brainpoolP160r1", L"brainpoolP160t1", L"brainpoolP192r1", L"brainpoolP192t1", L"brainpoolP224r1",
    L"brainpoolP224t1", L"brainpoolP256r1", L"brainpoolP256t1", L"brainpoolP320r1", L"brainpoolP320t1",
    L"brainpoolP384r1", L"brainpoolP384t1", L"brainpoolP512r1", L"brainpoolP512t1", L"curve25519",
    L"ec192wapi", L"nistP192", L"nistP224", L"nistP256", L"nistP384", L"nistP521", L"numsP256t1",
    L"numsP384t1", L"numsP512t1", L"secP160k1", L"secP160r1", L"secP160r2", L"secP192k1", L"secP192r1",
    L"secP224k1", L"secP224r1", L"secP256k1", L"secP256r1", L"secP384r1", L"secP521r1", L"wtls12", L"wtls7",
    L"wtls9", L"x962P192v1", L"x962P192v2", L"x962P192v3", L"x962P239v1", L"x962P239v2", L"x962P239v3",
    L"x962P256v1",
};

/* A generic ECC blob names its curve in the parameters, as .NET's ECDsaCng.ImportParameters passes it.
 * A missing or malformed name, or a known curve other than P-256, gives NTE_NOT_SUPPORTED, as on Windows;
 * an unknown curve name gives NTE_INVALID_PARAMETER. */
static SECURITY_STATUS check_generic_curve_params(const NCryptBufferDesc *params)
{
    const NCryptBuffer *buffer = NULL;
    const WCHAR *name;
    ULONG i, len;

    if (!params || params->ulVersion != NCRYPTBUFFER_VERSION || !params->cBuffers || !params->pBuffers)
        return NTE_NOT_SUPPORTED;
    for (i = 0; i < params->cBuffers; i++)
    {
        if (params->pBuffers[i].BufferType != NCRYPTBUFFER_ECC_CURVE_NAME) continue;
        buffer = &params->pBuffers[i];
        break;
    }
    if (!buffer || !(name = buffer->pvBuffer) || !buffer->cbBuffer || buffer->cbBuffer % sizeof(WCHAR))
        return NTE_NOT_SUPPORTED;
    for (len = 0; len < buffer->cbBuffer / sizeof(WCHAR); len++) if (!name[len]) break;
    if (len == buffer->cbBuffer / sizeof(WCHAR)) return NTE_NOT_SUPPORTED;

    for (i = 0; i < ARRAY_SIZE(known_curves); i++) if (!lstrcmpiW(name, known_curves[i])) break;
    if (i == ARRAY_SIZE(known_curves)) return NTE_INVALID_PARAMETER;
    if (lstrcmpiW(name, BCRYPT_ECC_CURVE_NISTP256) && lstrcmpiW(name, BCRYPT_ECC_CURVE_SECP256R1) &&
        lstrcmpiW(name, L"x962P256v1"))
        return NTE_NOT_SUPPORTED;
    return ERROR_SUCCESS;
}

static BOOL is_rsa_blob_type(const WCHAR *type)
{
    return !wcscmp(type, BCRYPT_RSAPUBLIC_BLOB) || !wcscmp(type, BCRYPT_RSAPRIVATE_BLOB) ||
           !wcscmp(type, BCRYPT_RSAFULLPRIVATE_BLOB);
}

/* Imports a P-256 key from a blob with a P-256 magic. A key imported from a generic blob reports the
 * algorithm "ECDSA" and its curve name, as on Windows. */
static SECURITY_STATUS import_ecdsa_p256(NCRYPT_PROV_HANDLE provider, BOOL private, BOOL generic, BYTE *data,
                                         DWORD datasize, struct object **ret_object)
{
    struct object *object;
    SECURITY_STATUS ret;
    NTSTATUS status;
    DWORD bitlen = 256;

    if (!(object = create_key_object(ECDSA_P256, provider)))
    {
        ERR("Error allocating memory\n");
        return NTE_NO_MEMORY;
    }

    status = BCryptImportKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, NULL,
                                 private ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_ECCPUBLIC_BLOB,
                                 &object->key.bcrypt_key, data, datasize, 0);
    if (status != STATUS_SUCCESS)
    {
        WARN("Error importing key pair %#lx\n", status);
        free_object(object);
        return map_ntstatus(status);
    }

    if (generic &&
        ((ret = set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)BCRYPT_ECDSA_ALGORITHM,
                                    sizeof(BCRYPT_ECDSA_ALGORITHM))) ||
         (ret = set_object_property(object, BCRYPT_ECC_CURVE_NAME, (BYTE *)BCRYPT_ECC_CURVE_NISTP256,
                                    sizeof(BCRYPT_ECC_CURVE_NISTP256)))))
    {
        BCryptDestroyKey(object->key.bcrypt_key);
        free_object(object);
        return ret;
    }
    if ((ret = set_key_length(object, bitlen))) return ret;
    *ret_object = object;
    return ERROR_SUCCESS;
}

/* The status Windows returns for a P-256 blob under the given blob type, or ERROR_SUCCESS. */
static SECURITY_STATUS check_p256_blob_type(const WCHAR *type, BOOL private)
{
    if (!type) return NTE_INVALID_PARAMETER;
    if (is_rsa_blob_type(type)) return NTE_BAD_DATA;
    if (private)
    {
        if (!wcscmp(type, BCRYPT_ECCPRIVATE_BLOB) || !wcscmp(type, BCRYPT_PRIVATE_KEY_BLOB)) return ERROR_SUCCESS;
        return NTE_INVALID_PARAMETER;
    }
    if (!wcscmp(type, BCRYPT_ECCPUBLIC_BLOB) || !wcscmp(type, BCRYPT_PUBLIC_KEY_BLOB)) return ERROR_SUCCESS;
    if (!wcscmp(type, BCRYPT_PRIVATE_KEY_BLOB) || !wcscmp(type, BCRYPT_ECCPRIVATE_BLOB)) return NTE_NOT_SUPPORTED;
    return NTE_INVALID_PARAMETER;
}

SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE decrypt_key,
                                       const WCHAR *type, NCryptBufferDesc *params, NCRYPT_KEY_HANDLE *handle,
                                       BYTE *data, DWORD datasize, DWORD flags)
{
    BCRYPT_KEY_BLOB *header = (BCRYPT_KEY_BLOB *)data;
    struct object *object;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %p, %lu, %#lx)\n", provider, decrypt_key, wine_dbgstr_w(type),
          params, handle, data, datasize, flags);

    if (decrypt_key)
    {
        FIXME("Key blob decryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!header || datasize < sizeof(*header))
    {
        WARN("Blob of %lu bytes is too small\n", datasize);
        return NTE_INVALID_PARAMETER;
    }

    switch (header->Magic)
    {
    case BCRYPT_RSAFULLPRIVATE_MAGIC:
    case BCRYPT_RSAPRIVATE_MAGIC:
    case BCRYPT_RSAPUBLIC_MAGIC:
    {
        NTSTATUS status;
        BCRYPT_RSAKEY_BLOB *rsablob = (BCRYPT_RSAKEY_BLOB *)data;

        if (params)
        {
            FIXME("Parameter information not implemented\n");
            return NTE_NOT_SUPPORTED;
        }
        if (!(object = create_key_object(RSA, provider)))
        {
            ERR("Error allocating memory\n");
            return NTE_NO_MEMORY;
        }

        status = BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, NULL, type, &object->key.bcrypt_key, data, datasize, 0);
        if (status != STATUS_SUCCESS)
        {
            WARN("Error importing key pair %#lx\n", status);
            free_object(object);
            return map_ntstatus(status);
        }

        if ((status = set_key_length(object, rsablob->BitLength))) return status;
        break;
    }
    case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
    case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
    {
        /* Windows ignores the parameters for a blob that names its curve in the magic. */
        BOOL private = header->Magic == BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        SECURITY_STATUS ret;

        if ((ret = check_p256_blob_type(type, private)))
        {
            WARN("Blob type %s does not fit magic %#lx\n", wine_dbgstr_w(type), header->Magic);
            return ret;
        }
        ret = import_ecdsa_p256(provider, private, FALSE, data, datasize, &object);
        if (ret != ERROR_SUCCESS) return ret;
        break;
    }
    case BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC:
    case BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC:
    {
        BCRYPT_ECCKEY_BLOB *copy;
        SECURITY_STATUS ret;
        BOOL private = header->Magic == BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC;
        DWORD public_size, size = datasize;

        if (!type) return NTE_INVALID_PARAMETER;
        if (is_rsa_blob_type(type)) return NTE_BAD_DATA;
        if ((ret = check_generic_curve_params(params)))
        {
            WARN("Unsupported curve parameters for a generic ECDSA blob\n");
            return ret;
        }
        /* Windows imports a generic private blob as a public one under BCRYPT_ECCPUBLIC_BLOB. Whether it keeps
         * the private part is not known; this keeps only the public part. */
        if (!wcscmp(type, BCRYPT_ECCPUBLIC_BLOB)) private = FALSE;
        else if (!private || wcscmp(type, BCRYPT_ECCPRIVATE_BLOB))
        {
            WARN("Blob type %s does not fit magic %#lx\n", wine_dbgstr_w(type), header->Magic);
            return NTE_NOT_SUPPORTED;
        }
        if (datasize < sizeof(*copy) || ((BCRYPT_ECCKEY_BLOB *)data)->cbKey != 32) return NTE_NOT_SUPPORTED;
        public_size = sizeof(*copy) + 2 * 32;
        if (!private && size > public_size) size = public_size;
        if (!(copy = malloc(size))) return NTE_NO_MEMORY;
        memcpy(copy, data, size);
        copy->dwMagic = private ? BCRYPT_ECDSA_PRIVATE_P256_MAGIC : BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        ret = import_ecdsa_p256(provider, private, TRUE, (BYTE *)copy, size, &object);
        free(copy);
        if (ret != ERROR_SUCCESS) return ret;
        break;
    }
    default:
        FIXME("Unhandled key magic %#lx\n", header->Magic);
        return NTE_INVALID_PARAMETER;
    }

    *handle = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptExportKey(NCRYPT_KEY_HANDLE key, NCRYPT_KEY_HANDLE encrypt_key, const WCHAR *type,
                                       NCryptBufferDesc *params, BYTE *output, DWORD output_len, DWORD *ret_len,
                                       DWORD flags)
{
    struct object *object = (struct object *)key;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %lu, %p, %#lx)\n", key, encrypt_key, wine_dbgstr_w(type), params, output,
          output_len, ret_len, flags);

    if (encrypt_key)
    {
        FIXME("Key blob encryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }

    return map_ntstatus(BCryptExportKey(object->key.bcrypt_key, NULL, type, output, output_len, ret_len, 0));
}

SECURITY_STATUS WINAPI NCryptIsAlgSupported(NCRYPT_PROV_HANDLE provider, const WCHAR *algid, DWORD flags)
{
    static const ULONG supported = BCRYPT_CIPHER_OPERATION |\
                                   BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |\
                                   BCRYPT_SIGNATURE_OPERATION |\
                                   BCRYPT_SECRET_AGREEMENT_OPERATION;
    BCRYPT_ALGORITHM_IDENTIFIER *list;
    ULONG i, count;
    NTSTATUS status;

    TRACE("(%#Ix, %s, %#lx)\n", provider, wine_dbgstr_w(algid), flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!lstrcmpiW(BCRYPT_RSA_SIGN_ALGORITHM, algid)) return NTE_NOT_SUPPORTED;

    status = BCryptEnumAlgorithms(supported, &count, &list, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error retrieving algorithm list %#lx\n", status);
        return map_ntstatus(status);
    }

    status = STATUS_NOT_SUPPORTED;
    for (i = 0; i < count; i++)
    {
        if (!lstrcmpiW(list[i].pszName, algid))
        {
            status = STATUS_SUCCESS;
            break;
        }
    }

    BCryptFreeBuffer(list);
    return map_ntstatus(status);
}

BOOL WINAPI NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    FIXME("(%#Ix): stub\n", hKey);
    return FALSE;
}

SECURITY_STATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                     const WCHAR *name, DWORD keyspec, DWORD flags)
{
    FIXME("(%#Ix, %p, %s, %#lx, %#lx): stub\n", provider, key, wine_dbgstr_w(name), keyspec, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *provider, const WCHAR *name, DWORD flags)
{
    struct object *object;

    FIXME("(%p, %s, %#lx): stub\n", provider, wine_dbgstr_w(name), flags);

    if (!(object = allocate_object(STORAGE_PROVIDER)))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }
    *provider = (NCRYPT_PROV_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *input, DWORD insize, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %s, %p, %lu, %#lx)\n", handle, wine_dbgstr_w(name), input, insize, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (!wcscmp(name, NCRYPT_PROVIDER_HANDLE_PROPERTY)) return NTE_NOT_SUPPORTED;
    return set_object_property(object, name, input, insize);
}

SECURITY_STATUS WINAPI NCryptSignHash(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *value, DWORD value_len,
                                      BYTE *sig, DWORD sig_len, DWORD *ret_len, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, value, value_len, sig, sig_len, flags);
    if (flags & NCRYPT_SILENT_FLAG) FIXME("Silent flag not implemented\n");

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptSignHash(object->key.bcrypt_key, padding, value, value_len, sig, sig_len,
                                       ret_len, flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptVerifySignature(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *hash, DWORD hash_size,
                                             BYTE *signature, DWORD signature_size, DWORD flags)
{
    struct object *key_object = (struct object *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, hash, hash_size, signature,
          signature_size, flags);

    if (!hash_size || !signature_size) return NTE_INVALID_PARAMETER;
    if (!hash || !signature) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (!handle || key_object->type != KEY) return NTE_INVALID_HANDLE;

    if (key_object->key.algid < RSA)
    {
        FIXME("Symmetric keys not supported.\n");
        return NTE_NOT_SUPPORTED;
    }

    return map_ntstatus(BCryptVerifySignature(key_object->key.bcrypt_key, padding, hash, hash_size, signature,
                                              signature_size, flags));
}
