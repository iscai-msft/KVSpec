# Azure KeyVault Certificates API Design

Azure Key Vault is a cloud service that provides secure storage and automated management of certificates used throughout a cloud application. Multiple certificate, and multiple versions of the same certificate, can be kept in the Key Vault. Each certificate in the vault has a policy associated with it which controls the issuance and lifetime of the certificate, along with actions to be taken as certificates near expiry.

The Azure Key Vault Certificate client library enables programmatically managing certificates, offering methods to create, update, list, and delete certificates, policies, issuers, and contacts. The library also supports managing pending certificate operations and management of deleted certificates.

## Concepts
* Certificate
* Certificate Policy
* Issuer
* Contact
* Certificate Operation

## Scenario - Get vault endpoint

### API

#### Java
```java
public String getVaultUrl();
```

#### .NET
```c#
public virtual Uri VaultUri { get; }
```

#### Python
```python
certificate_client.vault_url
```

#### JS/TS

```ts
  public readonly vaultUrl: string;
```

### API
### Java
```java

public PollerFlux<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy, boolean isEnabled, Map<String, String> tags)
public PollerFlux<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy)

public SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy, boolean isEnabled, Map<String, String> tags)
public SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy)
```

### .NET
```c#
public virtual CertificateOperation StartCreateCertificate(string certificateName, CertificatePolicy policy, bool? enabled = null, IDictionary<string, string> tags = null, CancellationToken cancellationToken = default);
public virtual Task<CertificateOperation> StartCreateCertificateAsync(string certificateName, CertificatePolicy policy, bool? enabled = null, IDictionary<string, string> tags = null, CancellationToken cancellationToken = default);
```

### Python
//Async
```python
    async def create_certificate(
        self,
        certificate_name,  # type: str
        policy,  # type: CertificatePolicy
        **kwargs  # type: Any
    ) -> KeyVaultCertificate
    :keyword bool enabled: Whether the certificate is enabled for use.
        :keyword tags: Application specific metadata in the form of key-value pairs.
        :paramtype tags: dict[str, str]
```

//Sync
```python
    def begin_create_certificate(
        self,
        certificate_name,  # type: str
        policy,  # type: CertificatePolicy
        **kwargs  # type: Any
    ) -> LROPoller[KeyVaultCertificate]
    :keyword bool enabled: Whether the certificate is enabled for use.
    :keyword tags: Application specific metadata in the form of key-value pairs.
    :paramtype tags: dict[str, str]
```
### JS/TS
```ts
  public async beginCreateCertificate(
    certificateName: string,
    policy: CertificatePolicy,
    options: BeginCreateCertificateOptions = {}
  ): Promise<
    PollerLike<PollOperationState<KeyVaultCertificateWithPolicy>, KeyVaultCertificateWithPolicy>
  >
```
### API
### Java
```java
// Async API
public Mono<KeyVaultCertificateWithPolicy> getCertificate(String certificateName)
public Mono<Response<KeyVaultCertificateWithPolicy>> getCertificateWithResponse(String certificateName)
public Mono<Response<KeyVaultCertificate>> getCertificateVersionWithResponse(String certificateName, String version)
public Mono<KeyVaultCertificate> getCertificateVersion(String certificateName, String version) {}

//Sync API
public KeyVaultCertificateWithPolicy getCertificate(String certificateName)
public Response<KeyVaultCertificateWithPolicy> getCertificateWithResponse(String certificateName)
public Response<KeyVaultCertificate> getCertificateVersionWithResponse(String certificateName, String version, Context context)
public KeyVaultCertificate getCertificateVersion(String certificateName, String version)
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> GetCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> GetCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
public virtual Response<KeyVaultCertificate> GetCertificateVersion(string certificateName, string version, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificate>> GetCertificateVersionAsync(string certificateName, string version, CancellationToken cancellationToken = default);
```

### Python
```python
async def get_certificate(self, certificate_name: str, **kwargs: "Any") -> KeyVaultCertificate:
async def get_certificate_version(
  self, certificate_name: str, version: str, **kwargs: "Any"
) -> KeyVaultCertificate:
```

### JS/TS
```javascript
  public async getCertificate(
    certificateName: string,
    options: GetCertificateOptions = {}
  ): Promise<KeyVaultCertificateWithPolicy>

  public async getCertificateVersion(
    certificateName: string,
    version: string,
    options: GetCertificateVersionOptions = {}
  ): Promise<KeyVaultCertificate>
```

### API
### Java
```java
public Mono<CertificatePolicy> getCertificatePolicy(String certificateName)
public Mono<Response<CertificatePolicy>> getCertificatePolicyWithResponse(String certificateName)

public CertificatePolicy getCertificatePolicy(String certificateName)
public Response<CertificatePolicy> getCertificatePolicyWithResponse(String certificateName, Context context)
```

### .NET
```c#
public virtual Response<CertificatePolicy> GetCertificatePolicy(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificatePolicy>> GetCertificatePolicyAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_certificate_policy(self, certificate_name: str, **kwargs: "Any") -> CertificatePolicy:
```

### JS/TS
```ts
  public async getCertificatePolicy(
    certificateName: string,
    options: GetCertificatePolicyOptions = {}
  ): Promise<CertificatePolicy>
```

### API
### Java
```java

public Mono<KeyVaultCertificate> updateCertificateProperties(CertificateProperties properties)
public Mono<Response<KeyVaultCertificate>> updateCertificatePropertiesWithResponse(CertificateProperties properties)


public KeyVaultCertificate updateCertificateProperties(CertificateProperties properties)
public Response<KeyVaultCertificate> updateCertificatePropertiesWithResponse(CertificateProperties properties, Context context)
```

### .NET
```c#
public virtual Response<KeyVaultCertificate> UpdateCertificateProperties(CertificateProperties properties, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificate>> UpdateCertificatePropertiesAsync(CertificateProperties properties, CancellationToken cancellationToken = default);
```

### Python
```python
async def update_certificate_properties(
        self, certificate_name: str, version: Optional[str] = None, **kwargs: "Any"
    ) -> KeyVaultCertificate:
    :keyword bool enabled: Whether the certificate is enabled for use.
        :keyword tags: Application specific metadata in the form of key-value pairs.
        :paramtype tags: dict[str, str]
```

### JS/TS
```ts
  public async updateCertificateProperties(
    certificateName: string,
    version: string = "",
    options: UpdateCertificatePropertiesOptions = {}
  ): Promise<KeyVaultCertificate>
```

### API
### Java
```java
public Mono<CertificatePolicy> updateCertificatePolicy(String certificateName, CertificatePolicy policy)
public Mono<Response<CertificatePolicy>> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy)

public CertificatePolicy updateCertificatePolicy(String certificateName, CertificatePolicy policy)
public Response<CertificatePolicy> updateCertificatePolicyWithResponse(String certificateName, CertificatePolicy policy, Context context)
```

### .NET
```c#
public virtual Response<CertificatePolicy> UpdateCertificatePolicy(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificatePolicy>> UpdateCertificatePolicyAsync(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default);
```
### Python
```python
async def update_certificate_policy(
        self, certificate_name: str, policy: CertificatePolicy, **kwargs: "Any"
    ) -> CertificatePolicy:
```
### JS/TS
```ts
  public async updateCertificatePolicy(
    certificateName: string,
    policy: CertificatePolicy,
    options: UpdateCertificatePolicyOptions = {}
  ): Promise<CertificatePolicy>
```

### API
### Java
```java
public PollerFlux<DeletedCertificate, Void> beginDeleteCertificate(String certificateName)

public SyncPoller<DeletedCertificate, Void> beginDeleteCertificate(String certificateName)
```

### .NET
```c#
public virtual DeleteCertificateOperation StartDeleteCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<DeleteCertificateOperation> StartDeleteCertificateAsync(string certificateName, CancellationToken cancellationToken = default);

public class DeleteCertificateOperation : Operation<DeletedCertificate> {
    public override bool HasCompleted { get; }
    public override bool HasValue { get; }
    public override string Id { get; }
    public override DeletedCertificate Value { get; }
    public override Response GetRawResponse();
    public override Response UpdateStatus(CancellationToken cancellationToken = default);
    public override ValueTask<Response> UpdateStatusAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<DeletedCertificate>> WaitForCompletionAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<DeletedCertificate>> WaitForCompletionAsync(TimeSpan pollingInterval, CancellationToken cancellationToken);
}
```
### Python
//Async
```python
async def delete_certificate(self, certificate_name: str, **kwargs: "Any") -> DeletedCertificate:
```

//Sync
```python
# This LROPoller has a non-blocking result() call
def begin_delete_certificate(self, certificate_name, **kwargs) -> LROPoller[DeletedCertificate]
```
### JS/TS
```ts
  public async beginDeleteCertificate(
    certificateName: string,
    options: BeginDeleteCertificateOptions = {}
  ): Promise<PollerLike<PollOperationState<DeletedCertificate>, DeletedCertificate>>
```

### API
### Java
```java
//Async
public Mono<DeletedCertificate> getDeletedCertificate(String certificateName)
public Mono<Response<DeletedCertificate>> getDeletedCertificateWithResponse(String certificateName)

//Sync
public DeletedCertificate getDeletedCertificate(String certificateName)
public Response<DeletedCertificate> getDeletedCertificateWithResponse(String certificateName, Context context)
```

### .NET
```c#
public virtual Response<DeletedCertificate> GetDeletedCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<DeletedCertificate>> GetDeletedCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_deleted_certificate(self, certificate_name: str, **kwargs: "Any") -> DeletedCertificate:
```
### JS/TS
```ts
  public async getDeletedCertificate(
    certificateName: string,
    options: GetDeletedCertificateOptions = {}
  ): Promise<DeletedCertificate>
```

### API
### Java
```java
public PollerFlux<KeyVaultCertificateWithPolicy, Void> beginRecoverDeletedCertificate(String certificateName)

public SyncPoller<KeyVaultCertificateWithPolicy, Void> beginRecoverDeletedCertificate(String certificateName)
```

### .NET
```c#
public virtual RecoverDeletedCertificateOperation StartRecoverDeletedCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<RecoverDeletedCertificateOperation> StartRecoverDeletedCertificateAsync(string certificateName, CancellationToken cancellationToken = default);

public class RecoverDeletedCertificateOperation : Operation<KeyVaultCertificateWithPolicy> {
    public override bool HasCompleted { get; }
    public override bool HasValue { get; }
    public override string Id { get; }
    public override KeyVaultCertificateWithPolicy Value { get; }
    public override Response GetRawResponse();
    public override Response UpdateStatus(CancellationToken cancellationToken = default);
    public override ValueTask<Response> UpdateStatusAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(TimeSpan pollingInterval, CancellationToken cancellationToken);
}
```
### Python

//Async
```python
async def recover_deleted_certificate(self, certificate_name: str, **kwargs: "Any") -> KeyVaultCertificate:
```
//Sync
```python
def begin_recover_deleted_certificate(self, certificate_name, **kwargs) -> LROPoller[KeyVaultCertificate]
```
### JS/TS
```ts
  public async beginRecoverDeletedCertificate(
    certificateName: string,
    options: BeginRecoverDeletedCertificateOptions = {}
  ): Promise<PollerLike<PollOperationState<KeyVaultCertificate>, KeyVaultCertificate>>
```

### API
### Java
```java
public Mono<Void> purgeDeletedCertificate(String certificateName)
public Mono<Response<Void>> purgeDeletedCertificateWithResponse(String certificateName)

public void purgeDeletedCertificate(String certificateName)
public Response<Void> purgeDeletedCertificateWithResponse(String certificateName, Context context)
```

### .NET
```c#
public virtual Response PurgeDeletedCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response> PurgeDeletedCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def purge_deleted_certificate(self, certificate_name: str, **kwargs: "Any") -> None:
```
### JS/TS
```ts
  public async purgeDeletedCertificate(
    certificateName: string,
    options: PurgeDeletedCertificateOptions = {}
  ): Promise<null>
```

### API
### Java
```java
public Mono<byte[]> backupCertificate(String certificateName)
public Mono<Response<byte[]>> backupCertificateWithResponse(String certificateName)


public byte[] backupCertificate(String certificateName)
public Response<byte[]> backupCertificateWithResponse(String certificateName, Context context)

```

### .NET
```c#
public virtual Response<byte[]> BackupCertificate(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<Response<byte[]>> BackupCertificateAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def backup_certificate(self, certificate_name: str, **kwargs: "Any") -> bytes:
```
### JS/TS
```ts
  public async backupCertificate(
    certificateName: string,
    options: BackupCertificateOptions = {}
  ): Promise<Uint8Array | undefined>
```

### API
### Java
```java
public Mono<KeyVaultCertificateWithPolicy> restoreCertificateBackup(byte[] backup)
public Mono<Response<KeyVaultCertificateWithPolicy>> restoreCertificateBackupWithResponse(byte[] backup)

public KeyVaultCertificateWithPolicy restoreCertificateBackup(byte[] backup)
public Response<KeyVaultCertificateWithPolicy> restoreCertificateBackupWithResponse(byte[] backup, Context context)
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> RestoreCertificateBackup(byte[] backup, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> RestoreCertificateBackupAsync(byte[] backup, CancellationToken cancellationToken = default);
```
### Python
```python
async def restore_certificate_backup(self, backup: bytes, **kwargs: "Any") -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async restoreCertificateBackup(
    backup: Uint8Array,
    options: RestoreCertificateBackupOptions = {}
  ): Promise<KeyVaultCertificateWithPolicy>
```

### API
### Java
```java
public PagedFlux<CertificateProperties> listPropertiesOfCertificates(boolean includePending)
public PagedFlux<CertificateProperties> listPropertiesOfCertificates()

public PagedIterable<CertificateProperties> listPropertiesOfCertificates()
public PagedIterable<CertificateProperties> listPropertiesOfCertificates(boolean includePending, Context context)
```

### .NET
```c#
public virtual Pageable<CertificateProperties> GetPropertiesOfCertificates(bool includePending = false, CancellationToken cancellationToken = default);
public virtual AsyncPageable<CertificateProperties> GetPropertiesOfCertificatesAsync(bool includePending = false, CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_certificates(self, **kwargs: "Any") -> AsyncIterable[CertificateProperties]:
:keyword bool include_pending: Specifies whether to include certificates which are not
         completely provisioned.
```
### JS/TS
```ts
  public listPropertiesOfCertificates(
    options: ListPropertiesOfCertificatesOptions = {}
  ): PagedAsyncIterableIterator<CertificateProperties, CertificateProperties[]>
```

### API
### Java
```java
public PagedFlux<CertificateProperties> listPropertiesOfCertificateVersions(String certificateName)

public PagedIterable<CertificateProperties> listPropertiesOfCertificateVersions(String certificateName)
public PagedIterable<CertificateProperties> listPropertiesOfCertificateVersions(String certificateName, Context context)
```

### .NET
```c#
public virtual Pageable<CertificateProperties> GetPropertiesOfCertificateVersions(string certificateName, CancellationToken cancellationToken = default);
public virtual AsyncPageable<CertificateProperties> GetPropertiesOfCertificateVersionsAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_certificate_versions(
        self, certificate_name: str, **kwargs: "Any"
    ) -> AsyncIterable[CertificateProperties]:
```
### JS/TS
```ts
  public listPropertiesOfCertificateVersions(
    certificateName: string,
    options: ListPropertiesOfCertificateVersionsOptions = {}
  ): PagedAsyncIterableIterator<CertificateProperties, CertificateProperties[]>
```

### API
### Java
```java
public PagedFlux<DeletedCertificate> listDeletedCertificates()
public PagedFlux<DeletedCertificate> listDeletedCertificates(Boolean includePending)

public PagedIterable<DeletedCertificate> listDeletedCertificates()
public PagedIterable<DeletedCertificate> listDeletedCertificates(Boolean includePending, Context context)
```

### .NET
```c#
public virtual Pageable<DeletedCertificate> GetDeletedCertificates(bool includePending = false, CancellationToken cancellationToken = default);
public virtual AsyncPageable<DeletedCertificate> GetDeletedCertificatesAsync(bool includePending = false, CancellationToken cancellationToken = default);
```

### Python
```python
def list_deleted_certificates(self, **kwargs: "Any") -> AsyncIterable[DeletedCertificate]:
:keyword bool include_pending: Specifies whether to include certificates which are
         not completely deleted.
```

### JS/TS
```javascript
  public listDeletedCertificates(
    options: ListDeletedCertificatesOptions = {}
  ): PagedAsyncIterableIterator<DeletedCertificate, DeletedCertificate[]>
```


### API
### Java
```java
public Mono<CertificateIssuer> createIssuer(CertificateIssuer issuer)
public Mono<Response<CertificateIssuer>> createIssuerWithResponse(CertificateIssuer issuer)

public CertificateIssuer createIssuer(CertificateIssuer issuer)
public Response<CertificateIssuer> createIssuerWithResponse(CertificateIssuer issuer, Context context)
```

### .NET
```c#
public virtual Response<CertificateIssuer> CreateIssuer(CertificateIssuer issuer, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> CreateIssuerAsync(CertificateIssuer issuer, CancellationToken cancellationToken = default);
```
### Python
```python
async def create_issuer(
        self, issuer_name: str, provider: str, **kwargs: "Any"
    ) -> CertificateIssuer:
:keyword bool enabled: Whether the issuer is enabled for use.
:keyword str account_id: The user name/account name/account id.
:keyword str password: The password/secret/account key.
:keyword str organization_id: Id of the organization
:keyword admin_contacts: Contact details of the organization administrators of the
    certificate issuer.
:paramtype admin_contacts: list[~azure.keyvault.certificates.AdministratorContact]
```
### JS/TS
```javascript
  public async createIssuer(
    issuerName: string,
    provider: string,
    options: CreateIssuerOptions = {}
  ): Promise<CertificateIssuer>
```

### API
### Java
```java
public Mono<Response<CertificateIssuer>> getIssuerWithResponse(String issuerName)
public Mono<CertificateIssuer> getIssuer(String issuerName)

public Response<CertificateIssuer> getIssuerWithResponse(String issuerName, Context context)
public CertificateIssuer getIssuer(String issuerName)
```

### .NET
```c#
public virtual Response<CertificateIssuer> GetIssuer(string issuerName, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> GetIssuerAsync(string issuerName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_issuer(self, issuer_name: str, **kwargs: "Any") -> CertificateIssuer:
```
### JS/TS
```ts
  public async getIssuer(
    issuerName: string,
    options: GetIssuerOptions = {}
  ): Promise<CertificateIssuer>
```

### API
### Java
```java
public Mono<Response<CertificateIssuer>> deleteIssuerWithResponse(String issuerName)
public Mono<CertificateIssuer> deleteIssuer(String issuerName)


public Response<CertificateIssuer> deleteIssuerWithResponse(String issuerName, Context context)
public CertificateIssuer deleteIssuer(String issuerName)
```

### .NET
```c#
public virtual Response<CertificateIssuer> DeleteIssuer(string issuerName, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> DeleteIssuerAsync(string issuerName, CancellationToken cancellationToken = default);
```
### Python
```python
async def delete_issuer(self, issuer_name: str, **kwargs: "Any") -> CertificateIssuer:

```
### JS/TS
```ts
  public async deleteIssuer(
    issuerName: string,
    options: DeleteIssuerOptions = {}
  ): Promise<CertificateIssuer>
```

### API
### Java
```java
public PagedFlux<IssuerProperties> listPropertiesOfIssuers()

public PagedIterable<IssuerProperties> listPropertiesOfIssuers()
public PagedIterable<IssuerProperties> listPropertiesOfIssuers(Context context)
```

### .NET
```c#
public virtual Pageable<IssuerProperties> GetPropertiesOfIssuers(CancellationToken cancellationToken = default);
public virtual AsyncPageable<IssuerProperties> GetPropertiesOfIssuersAsync(CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_issuers(self, **kwargs: "Any") -> AsyncIterable[IssuerProperties]:
```
### JS/TS
```ts
  public listPropertiesOfIssuers(
    options: ListPropertiesOfIssuersOptions = {}
  ): PagedAsyncIterableIterator<IssuerProperties, IssuerProperties[]>
```

### API
### Java
```java
public Mono<CertificateIssuer> updateIssuer(CertificateIssuer issuer)
public Mono<Response<CertificateIssuer>> updateIssuerWithResponse(CertificateIssuer issuer)

public CertificateIssuer updateIssuer(CertificateIssuer issuer)
public Response<CertificateIssuer> updateIssuerWithResponse(CertificateIssuer issuer, Context context)
```

### .NET
```c#
public virtual Response<CertificateIssuer> UpdateIssuer(CertificateIssuer issuer, CancellationToken cancellationToken = default);
public virtual Task<Response<CertificateIssuer>> UpdateIssuerAsync(CertificateIssuer issuer, CancellationToken cancellationToken = default);
```
### Python
```python
async def update_issuer(self, issuer_name: str, **kwargs: "Any") -> CertificateIssuer:
:keyword bool enabled: Whether the issuer is enabled for use.
:keyword str provider: The issuer provider
:keyword str account_id: The user name/account name/account id.
:keyword str password: The password/secret/account key.
:keyword str organization_id: Id of the organization
:keyword admin_contacts: Contact details of the organization administrators of
    the certificate issuer
:paramtype admin_contacts: list[~azure.keyvault.certificates.AdministratorContact]
```
### JS/TS
```ts
  public async updateIssuer(
    issuerName: string,
    options: UpdateIssuerOptions = {}
  ): Promise<CertificateIssuer>
```

### API
### Java
```java
public PollerFlux<CertificateOperation, KeyVaultCertificateWithPolicy> getCertificateOperation(String certificateName)

public SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> getCertificateOperation(String certificateName)
```

### .NET
```c#
public virtual CertificateOperation GetCertificateOperation(string certificateName, CancellationToken cancellationToken = default);
public virtual Task<CertificateOperation> GetCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default);
```
### Python
```python
async def get_certificate_operation(self, certificate_name: str, **kwargs: "Any") -> CertificateOperation:
```
### JS/TS
```ts
  public async getCertificateOperation(
    certificateName: string,
    options: GetCertificateOperationOptions = {}
  ): Promise<PollerLike<PollOperationState<CertificateOperation>, CertificateOperation>>
```

### API
### Java
```java

--------- REMOVED------------------
public Mono<CertificateOperation> cancelCertificateOperation(String certificateName);
public Mono<Response<CertificateOperation>> cancelCertificateOperation(String certificateName);

public CertificateOperation cancelCertificateOperation(String certificateName);
public Response<CertificateOperation> cancelCertificateOperation(String certificateName);
```

### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy>
{
    public virtual void Cancel(CancellationToken cancellationToken = default);
    public virtual Task CancelAsync(CancellationToken cancellationToken = default);
}
```
### Python
```python
async def cancel_certificate_operation(self, certificate_name: str, **kwargs: "Any") -> CertificateOperation:
```
### JS/TS
```ts
  private async cancelCertificateOperation(
    certificateName: string,
    options: CancelCertificateOperationOptions = {}
  ): Promise<CertificateOperation>
```

### API
### Java
```java
public Mono<CertificateOperation> deleteCertificateOperation(String certificateName)
public Mono<Response<CertificateOperation>> deleteCertificateOperationWithResponse(String certificateName)

public CertificateOperation deleteCertificateOperation(String certificateName)
public Response<CertificateOperation> deleteCertificateOperationWithResponse(String certificateName, Context context)
```

### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy>
{
    public virtual void Delete(CancellationToken cancellationToken = default);
    public virtual Task DeleteAsync(CancellationToken cancellationToken = default);
}
```
### Python
```python
async def delete_certificate_operation(self, certificate_name: str, **kwargs: "Any") -> CertificateOperation:
```
### JS/TS
```ts
  public async deleteCertificateOperation(
    certificateName: string,
    options: DeleteCertificateOperationOptions = {}
  ): Promise<CertificateOperation>
```

### API
### Java
```java
public PagedFlux<CertificateContact> setContacts(List<CertificateContact> contacts)

public PagedIterable<CertificateContact> setContacts(List<CertificateContact> contacts)
public PagedIterable<CertificateContact> setContacts(List<CertificateContact> contacts, Context context)
```

### .NET
```c#
public virtual Response<IList<CertificateContact>> SetContacts(IEnumerable<CertificateContact> contacts, CancellationToken cancellationToken = default);
public virtual Task<Response<IList<CertificateContact>>> SetContactsAsync(IEnumerable<CertificateContact> contacts, CancellationToken cancellationToken = default);
```
### Python
```python
async def set_contacts(
        self, contacts: Iterable[CertificateContact], **kwargs: "Any"
    ) -> List[CertificateContact]:
```
### JS/TS
```ts
  public async setContacts(
    contacts: CertificateContact[],
    options: SetContactsOptions = {}
  ): Promise<CertificateContact[] | undefined>
```

### API
### Java
```java
public PagedFlux<CertificateContact> listContacts()

public PagedIterable<CertificateContact> listContacts()
public PagedIterable<CertificateContact> listContacts(Context context)
```

### .NET
```c#
public virtual Response<IList<CertificateContact>> GetContacts(CancellationToken cancellationToken = default);
public virtual Task<Response<IList<CertificateContact>>> GetContactsAsync(CancellationToken cancellationToken = default);
```
### Python
```python
async def get_contacts(self, **kwargs: "Any") -> List[CertificateContact]:
```
### JS/TS
```ts
  public async getContacts(
    options: GetContactsOptions = {}
  ): Promise<CertificateContact[] | undefined>
```

### API

### Java
```java
public PagedFlux<CertificateContact> deleteContacts()

public PagedIterable<CertificateContact> deleteContacts()
public PagedIterable<CertificateContact> deleteContacts(Context context)
```

### .NET
```c#
public virtual Response<IList<CertificateContact>> DeleteContacts(CancellationToken cancellationToken = default);
public virtual Task<Response<IList<CertificateContact>>> DeleteContactsAsync(CancellationToken cancellationToken = default);
```
### Python
```python
async def delete_contacts(self, **kwargs: "Any") -> List[CertificateContact]:
```
### JS/TS
```ts
  public async deleteContacts(
    options: DeleteContactsOptions = {}
  ): Promise<CertificateContact[] | undefined>
```

### API
### Java
Removed

### .NET
```c#
Not in Master.
```
### Python
Removed
### JS/TS
```ts
Not in Master
```

### API
### Java
```java
public Mono<KeyVaultCertificate> mergeCertificate(MergeCertificateOptions mergeCertificateOptions)
public Mono<Response<KeyVaultCertificateWithPolicy>> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateOptions)

public KeyVaultCertificateWithPolicy mergeCertificate(MergeCertificateOptions mergeCertificateOptions)
public Response<KeyVaultCertificateWithPolicy> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateOptions, Context context)
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> MergeCertificate(MergeCertificateOptions mergeCertificateOptions, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> MergeCertificateAsync(MergeCertificateOptions mergeCertificateOptions, CancellationToken cancellationToken = default);
```
### Python
```python
async def merge_certificate(
        self, certificate_name: str, x509_certificates: List[bytearray], **kwargs: "Any"
    ) -> KeyVaultCertificate:
:keyword bool enabled: Whether the certificate is enabled for use.
:keyword tags: Application specific metadata in the form of key-value pairs.
:paramtype tags: dict[str, str]
```
### JS/TS
```ts
  public async mergeCertificate(
    certificateName: string,
    x509Certificates: Uint8Array[],
    options: MergeCertificateOptions = {}
  ): Promise<KeyVaultCertificateWithPolicy>
```

### API
### Java
```java
public Mono<KeyVaultCertificateWithPolicy> importCertificate(ImportCertificateOptions importCertificateOptions)
public Mono<Response<KeyVaultCertificateWithPolicy>> importCertificateWithResponse(ImportCertificateOptions importCertificateOptions)

public KeyVaultCertificateWithPolicy importCertificate(ImportCertificateOptions importCertificateOptions)
public Response<KeyVaultCertificateWithPolicy> importCertificateWithResponse(ImportCertificateOptions importCertificateOptions, Context context)
```

### .NET
```c#
public virtual Response<KeyVaultCertificateWithPolicy> ImportCertificate(ImportCertificateOptions importCertificateOptions, CancellationToken cancellationToken = default);
public virtual Task<Response<KeyVaultCertificateWithPolicy>> ImportCertificateAsync(ImportCertificateOptions importCertificateOptions, CancellationToken cancellationToken = default);
```

### Python
```python
async def import_certificate(
        self, certificate_name: str, certificate_bytes: bytes, **kwargs: "Any"
    ) -> KeyVaultCertificate:
:keyword bool enabled: Whether the certificate is enabled for use.
:keyword tags: Application specific metadata in the form of key-value pairs.
:paramtype tags: dict[str, str]
:keyword str password: If the private key in the passed in certificate is encrypted, it
    is the password used for encryption.
:keyword policy: The management policy for the certificate
:paramtype policy: ~azure.keyvault.certificates.CertificatePolicy
```
### JS/TS
```ts
  public async importCertificate(
    certificateName: string,
    certificateValue: Uint8Array,
    options: ImportCertificateOptions = {}
  ): Promise<KeyVaultCertificateWithPolicy>
```

## Certifciates Datastructures Design
## KeyVaultCertificate
### .NET
```c#
public class KeyVaultCertificate : IJsonDeserializable {
    public byte[] Cer { get; }
    public Uri Id { get; }
    public Uri KeyId { get; }
    public string Name { get; }
    public CertificateProperties Properties { get; }
    public Uri SecretId { get; }
}
```

### Java
```java
public class KeyVaultCertificate {
    public CertificateProperties getProperties()
    public KeyVaultCertificate setProperties(CertificateProperties properties)
    public String getId()
    public String getName()
    public String getKeyId()
    public String getSecretId()
    public byte[] getCer()
}
```

### Python
```python
def __init__(
        self,
        policy,  # type: CertificatePolicy
        properties=None,  # type: Optional[CertificateProperties]
        cer=None,  # type: Optional[bytes]
        **kwargs  # type: Any
    ):

    @property
    def id(self):
        # type: () -> str
    @property
    def name(self):
        # type: () -> str
    @property
    def properties(self):
        # type: () -> CertificateProperties
    @property
    def key_id(self):
        # type: () -> str
    @property
    def secret_id(self):
        # type: () -> str
    @property
    def policy(self):
        # type: () -> CertificatePolicy
    @property
    def cer(self):
        # type: () -> bytes
```
### JS/TS
```ts
export interface KeyVaultCertificate {
  cer?: Uint8Array;
  id?: string;
  readonly keyId?: string;
  readonly secretId?: string;
  readonly name: string;
  properties: CertificateProperties;
}
```

## KeyVaultCertificateWithPolicy
### .NET
```c#
public class KeyVaultCertificateWithPolicy : KeyVaultCertificate {
    public CertificatePolicy Policy { get; }
}
```

### Java
```java
// not seeing a getProperties
public class KeyVaultCertificateWithPolicy extends KeyVaultCertificate {
    public KeyVaultCertificateWithPolicy setProperties(CertificateProperties properties) {}
    public CertificatePolicy getCertificatePolicy() {}
    public KeyVaultCertificateWithPolicy setCertificatePolicy(CertificatePolicy certificatePolicy) {}
}
```

### Python
```python
N/A

```
### JS/TS
```ts
export interface KeyVaultCertificateWithPolicy extends KeyVaultCertificate {
  readonly policy?: CertificatePolicy;
}
```

## CertificateProperties
### .NET
```c#
public class CertificateProperties : IJsonDeserializable {
    public CertificateProperties(string name);
    public CertificateProperties(Uri id);
    public DateTimeOffset? CreatedOn { get; }
    public bool? Enabled { get; set; }
    public DateTimeOffset? ExpiresOn { get; }
    public Uri Id { get; }
    public string Name { get; }
    public DateTimeOffset? NotBefore { get; }
    public string RecoveryLevel { get; }
    public IDictionary<string, string> Tags { get; }
    public DateTimeOffset? UpdatedOn { get; }
    public Uri VaultUri { get; }
    public string Version { get; }
    public byte[] X509Thumbprint { get; }
}
```

### Java
```java
public class CertificateProperties {
    public String getId()
    public OffsetDateTime getNotBefore()
    public OffsetDateTime getExpiresOn()
    public OffsetDateTime getCreatedOn()
    public OffsetDateTime getUpdatedOn()
    public Map<String, String> getTags()
    public CertificateProperties setTags(Map<String, String> tags)
    public String getVersion()
    public String getName()
    public String getRecoveryLevel()
    public Boolean isEnabled()
    public CertificateProperties setEnabled(Boolean enabled)
    public byte[] getX509Thumbprint()
}
```

### Python
```python
def __init__(self, **kwargs):
  @property
    def id(self):
        # type: () -> str
    @property
    def name(self):
        # type: () -> str
    @property
    def enabled(self):
        # type: () -> bool
    @property
    def not_before(self):
        # type: () -> datetime
    @property
    def expires_on(self):
        # type: () -> datetime
    @property
    def created_on(self):
        # type: () -> datetime
    @property
    def updated_on(self):
        # type: () -> datetime
    @property
    def recovery_level(self):
        # type: () -> models.DeletionRecoveryLevel
    @property
    def vault_url(self):
        # type: () -> str
    @property
    def x509_thumbprint(self):
        # type: () -> bytes
    @property
    def tags(self):
        # type: () -> Dict[str, str]
    @property
    def version(self):
      # type: () -> str
```
### JS/TS
```ts
export interface CertificateProperties {
  readonly createdOn?: Date;
  enabled?: boolean;
  readonly expiresOn?: Date;
  readonly id?: string;
  readonly name?: string;
  notBefore?: Date;
  readonly recoveryLevel?: DeletionRecoveryLevel;
  tags?: CertificateTags;
  readonly updatedOn?: Date;
  vaultUrl?: string;
  readonly version?: string;
  readonly x509Thumbprint?: Uint8Array;
}
}
```

## CertificateOperation
### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy> {
    public CertificateOperation(Uri vaultUri, string name);
    public override bool HasCompleted { get; }
    public override bool HasValue { get; }
    public override string Id { get; }
    public CertificateOperationProperties Properties { get; }
    public override KeyVaultCertificateWithPolicy Value { get; }
    public virtual void Cancel(CancellationToken cancellationToken = default);
    public virtual Task CancelAsync(CancellationToken cancellationToken = default);
    public virtual void Delete(CancellationToken cancellationToken = default);
    public virtual Task DeleteAsync(CancellationToken cancellationToken = default);
    public override Response GetRawResponse();
    public override Response UpdateStatus(CancellationToken cancellationToken = default);
    public override ValueTask<Response> UpdateStatusAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(CancellationToken cancellationToken = default);
    public override ValueTask<Response<KeyVaultCertificateWithPolicy>> WaitForCompletionAsync(TimeSpan pollingInterval, CancellationToken cancellationToken);
}

public class CertificateOperationProperties : IJsonDeserializable {
    public bool CancellationRequested { get; }
    public bool? CertificateTransparency { get; }
    public string CertificateType { get; }
    public string Csr { get; }
    public CertificateOperationError Error { get; }
    public Uri Id { get; }
    public string IssuerName { get; }
    public string Name { get; }
    public string RequestId { get; }
    public string Status { get; }
    public string StatusDetails { get; }
    public string Target { get; }
    public Uri VaultUri { get; }
}
```

### Java
```java
public final class CertificateOperation {
    public String getId()
    public String getIssuerName()
    public String getCertificateType()
    public boolean isCertificateTransparent()
    public byte[] getCsr()
    public Boolean getCancellationRequested()
    public String getStatus()
    public String getStatusDetails()
    public CertificateOperationError getError()
    public String getTarget()
    public String getRequestId()
}
```

### Python
```python
def __init__(
        self,
        cert_operation_id=None,  # type: Optional[str]
        issuer_name=None,  # type: Optional[Union[str, WellKnownIssuerNames]]
        certificate_type=None,  # type: Optional[str]
        certificate_transparency=False,  # type: Optional[bool]
        csr=None,  # type: Optional[bytes]
        cancellation_requested=False,  # type: Optional[bool]
        status=None,  # type: Optional[str]
        status_details=None,  # type: Optional[str]
        error=None,  # type: Optional[CertificateOperatinError]
        target=None,  # type: Optional[str]
        request_id=None,  # type: Optional[str]
    ):

@property
    def id(self):
        # type: () -> str
    @property
    def name(self):
        # type: () -> str
    @property
    def issuer_name(self):
        # type: () -> str
    @property
    def certificate_type(self):
        # type: () -> str
    @property
    def certificate_transparency(self):
        # type: () -> bool
    @property
    def csr(self):
        # type: () -> bytes
    @property
    def cancellation_requested(self):
        # type: () -> bool
    @property
    def status(self):
        # type: () -> str
    @property
    def status_details(self):
        # type: () -> str
    @property
    def error(self):
        # type: () -> CertificateOperationError
    @property
    def target(self):
        # type: () -> str
    @property
    def request_id(self):
        # type: () -> str
```
### JS/TS
```ts
export interface CertificateOperation {
  readonly id?: string;
  issuerName?: string;
  certificateType?: string;
  certificateTransparency?: boolean;
  csr?: Uint8Array;
  cancellationRequested?: boolean;
  status?: string;
  statusDetails?: string;
  error?: CertificateOperationError;
  target?: string;
  requestId?: string;
}
```

## CertificateOperationError
### .NET
```c#
public class CertificateOperationError : IJsonDeserializable {
    public string Code { get; }
    public CertificateOperationError InnerError { get; }
    public string Message { get; }
}
```

### Java
```java
public class CertificateOperationError {
    public String getCode()
    public String getMessage()
    public CertificateOperationError getInnerError()
}
```

### Python
```python
def __init__(self, code, message, inner_error):
  @property
    def code(self):
        # type: () -> str
    @property
    def message(self):
        # type: () -> str
    @property
    def inner_error(self):
        # type: () -> CertificateOperationError
```
### JS/TS
```ts
export interface CertificateOperationError {
  readonly code?: string;
  readonly message?: string;
  readonly innerError?: CertificateOperationError;
}
```

## DeletedCertificate
### .NET
```c#
public class DeletedCertificate : KeyVaultCertificateWithPolicy {
    public DateTimeOffset? DeletedOn { get; }
    public Uri RecoveryId { get; }
    public DateTimeOffset? ScheduledPurgeDate { get; }
}
```

### Java
```java
public final class DeletedCertificate extends KeyVaultCertificate {
    public String getRecoveryId()
    public OffsetDateTime getScheduledPurgeDate()
    public OffsetDateTime getDeletedOn()
}
```

### Python
```python
def __init__(
        self,
        properties=None,  # type: Optional[CertificateProperties]
        policy=None,  # type: Optional[CertificatePolicy]
        cer=None,  # type: Optional[bytes]
        **kwargs  # type: Any
    ):
@property
    def deleted_on(self):
        # type: () -> datetime
    @property
    def recovery_id(self):
        # type: () -> str
    @property
    def scheduled_purge_date(self):
        # type: () -> datetime
```
### JS/TS
```ts
export interface DeletedCertificate extends KeyVaultCertificateWithPolicy {
  readonly deletedOn?: Date;
  recoveryId?: string;
  readonly scheduledPurgeDate?: Date;
}
```

## CertificatePolicy
### .NET
```c#
public class CertificatePolicy : IJsonSerializable, IJsonDeserializable {
    public CertificatePolicy(string issuerName, string subject);
    public CertificatePolicy(string issuerName, SubjectAlternativeNames subjectAlternativeNames);
    public CertificatePolicy(string issuerName, string subject, SubjectAlternativeNames subjectAlternativeNames);
    public static CertificatePolicy Default { get; }
    public bool? CertificateTransparency { get; set; }
    public string CertificateType { get; set; }
    public CertificateContentType? ContentType { get; set; }
    public DateTimeOffset? CreatedOn { get; }
    public bool? Enabled { get; set; }
    public IList<string> EnhancedKeyUsage { get; }
    public bool? Exportable { get; set; }
    public string IssuerName { get; }
    public CertificateKeyCurveName? KeyCurveName { get; set; }
    public int? KeySize { get; set; }
    public CertificateKeyType? KeyType { get; set; }
    public IList<CertificateKeyUsage> KeyUsage { get; }
    public IList<LifetimeAction> LifetimeActions { get; }
    public bool? ReuseKey { get; set; }
    public string Subject { get; }
    public SubjectAlternativeNames SubjectAlternativeNames { get; }
    public DateTimeOffset? UpdatedOn { get; }
    public int? ValidityInMonths { get; set; }


}
```

### Java
```java
public final class CertificatePolicy {
    public CertificatePolicy(String issuerName, String subject)
    public CertificatePolicy(String issuerName, SubjectAlternativeNames subjectAlternativeNames)
    public CertificatePolicy(String issuerName, String subject, SubjectAlternativeNames subjectAlternativeNames)
    public static CertificatePolicy getDefault()
    public Boolean isCertificateTransparent()
    public CertificatePolicy setCertificateTransparent(Boolean certificateTransparent)
    public String getCertificateType()
    public CertificatePolicy setCertificateType(String certificateType)
    public CertificateContentType getContentType()
    public CertificatePolicy setContentType(CertificateContentType contentType)
    public OffsetDateTime getCreatedOn()
    public Boolean isEnabled()
    public CertificatePolicy setEnabled(Boolean enabled)
    public List<String> getEnhancedKeyUsage()
    public CertificatePolicy setEnhancedKeyUsage(List<String> ekus)
    public Boolean isExportable()
    public CertificatePolicy setExportable(Boolean exportable)
    public String getIssuerName()
    public CertificatePolicy setIssuerName(String issuerName)
    public CertificateKeyCurveName getKeyCurveName()
    public CertificatePolicy setKeyCurveName(CertificateKeyCurveName keyCurveName)
    public Integer getKeySize()
    public CertificatePolicy setKeySize(Integer keySize)
    public CertificateKeyType getKeyType()
    public CertificatePolicy setKeyType(CertificateKeyType keyType)
    public List<CertificateKeyUsage> getKeyUsage()
    public CertificatePolicy setKeyUsage(CertificateKeyUsage... keyUsage)
    public List<LifetimeAction> getLifetimeActions()
    public CertificatePolicy setLifetimeActions(LifetimeAction... actions)
    public Boolean isKeyReusable()
    public CertificatePolicy setKeyReusable(Boolean keyReusable)
    public String getSubject() // not seeing a setSubject
    public SubjectAlternativeNames getSubjectAlternativeNames()
    public CertificatePolicy setSubjectAlternativeNames(SubjectAlternativeNames subjectAlternativeNames)
    public OffsetDateTime getUpdatedOn()
    public Integer getValidityInMonths()
    public CertificatePolicy setValidityInMonths(Integer validityInMonths)

}
```

### Python
```python
def __init__(
        self,
        issuer_name,  # type: str
        **kwargs  # type: Any
    ):
    def get_default(cls):

    @property
    def certificate_transparency(self):
        # type: () -> bool
    @property
    def certificate_type(self):
        # type: () -> str
    @property
    def content_type(self):
        # type: () -> CertificateContentType
    @property
    def created_on(self):
        # type: () -> datetime
    @property
    def enabled(self):
        # type: () -> bool
    @property
    def enhanced_key_usage(self):
        # type: () -> List[str]
    @property
    def exportable(self):
        # type: () -> bool
    @property
    def issuer_name(self):
        # type: () -> str
    @property
    def key_curve_name(self):
        # type: () -> KeyCurveName
    @property
    def key_size(self):
        # type: () -> int
    @property
    def key_type(self):
        # type: () -> KeyType
    @property
    def key_usage(self):
        # type: () -> List[KeyUsageType]
    @property
    def lifetime_actions(self):
        # type: () -> List[LifetimeAction]
    @property
    def reuse_key(self):
        # type: () -> bool
    @property
    def subject(self):
        # type: () -> str
    @property
    def san_emails(self):
        # type: () -> List[str]
    @property
    def san_dns_names(self):
        # type: () -> List[str]
    @property
    def san_user_principal_names(self):
        # type: () -> List[str]
    @property
    def updated_on(self):
        # type: () -> datetime
    @property
    def validity_in_months(self):
        # type: () -> int


    @property
    def id(self):
        # type: () -> str

    @property
    def not_before(self):
        # type: () -> datetime
    @property
    def expires_on(self):
        # type: () -> datetime

    @property
    def recovery_level(self):
        # type: () -> models.DeletionRecoveryLevel
```
### JS/TS
```ts
export type RequireAtLeastOne<T> = {
  [K in keyof T]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<keyof T, K>>>;
}[keyof T];

export interface CertificatePolicyProperties {
  certificateTransparency?: boolean;
  certificateType?: string;
  contentType?: CertificateContentType;
  readonly createdOn?: Date;
  enabled?: boolean;
  enhancedKeyUsage?: string[];
  exportable?: boolean;
  issuerName?: WellKnownIssuerNames | string;
  keyCurveName?: CertificateKeyCurveName;
  keySize?: number;
  keyType?: CertificateKeyType;
  keyUsage?: KeyUsageType[];
  lifetimeActions?: LifetimeAction[];
  reuseKey?: boolean;
  readonly updatedOn?: Date;
  validityInMonths?: number;
}

export interface PolicySubjectProperties {
  subject: string;
  subjectAlternativeNames: SubjectAlternativeNames;
}

export type CertificatePolicy = CertificatePolicyProperties &
  RequireAtLeastOne<PolicySubjectProperties>;
```


## CertificateContentType
### .NET
```c#
public struct CertificateContentType : IEquatable<CertificateContentType> {
    public CertificateContentType(string value);
    public static CertificateContentType Pem { get; }
    public static CertificateContentType Pkcs12 { get; }
    public static bool operator ==(CertificateContentType left, CertificateContentType right);
    public static implicit operator CertificateContentType(string value);
    public static bool operator !=(CertificateContentType left, CertificateContentType right);
    public bool Equals(CertificateContentType other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateContentType extends ExpandableStringEnum<CertificateContentType> {
    public static final CertificateContentType PKCS12 = fromString("application/x-pkcs12");
    public static final CertificateContentType PEM = fromString("application/x-pem-file");
    public static CertificateContentType fromString(String name)
    public static Collection<CertificateContentType> values()
}
```

### Python
```python
class CertificateContentType(str, Enum):
    """Content type of the secrets as specified in Certificate Policy"""

    pkcs12 = "application/x-pkcs12"
    pem = "application/x-pem-file"
```

### JS/TS
```ts
export type CertificateContentType = "application/x-pem-file" | "application/x-pkcs12" | undefined;
```


## CertificateKeyUsage
### .NET
```c#
public struct CertificateKeyUsage : IEquatable<CertificateKeyUsage> {
    public CertificateKeyUsage(string value);
    public static CertificateKeyUsage DigitalSignature { get; }
    public static CertificateKeyUsage NonRepudiation { get; }
    public static CertificateKeyUsage KeyEncipherment { get; }
    public static CertificateKeyUsage DataEncipherment { get; }
    public static CertificateKeyUsage KeyAgreement { get; }
    public static CertificateKeyUsage KeyCertSign { get; }
    public static CertificateKeyUsage CrlSign { get; }
    public static CertificateKeyUsage EncipherOnly { get; }
    public static CertificateKeyUsage DecipherOnly { get; }
    public static bool operator ==(CertificateKeyUsage left, CertificateKeyUsage right);
    public static implicit operator CertificateKeyUsage(string value);
    public static bool operator !=(CertificateKeyUsage left, CertificateKeyUsage right);
    public bool Equals(CertificateKeyUsage other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateKeyUsage extends ExpandableStringEnum<CertificateKeyUsage> {
    public static final CertificateKeyUsage DIGITAL_SIGNATURE = fromString("digitalSignature");
    public static final CertificateKeyUsage NON_REPUDIATION = fromString("nonRepudiation");
    public static final CertificateKeyUsage KEY_ENCIPHERMENT = fromString("keyEncipherment");
    public static final CertificateKeyUsage DATA_ENCIPHERMENT = fromString("dataEncipherment");
    public static final CertificateKeyUsage KEY_AGREEMENT = fromString("keyAgreement");
    public static final CertificateKeyUsage KEY_CERT_SIGN = fromString("keyCertSign");
    public static final CertificateKeyUsage CRL_SIGN = fromString("cRLSign");
    public static final CertificateKeyUsage ENCIPHER_ONLY = fromString("encipherOnly");
    public static final CertificateKeyUsage DECIPHER_ONLY = fromString("decipherOnly");
    public static CertificateKeyUsage fromString(String name) {}
    public static Collection<CertificateKeyUsage> values() {}
}
```

### Python
```python
class KeyUsageType(str, Enum):
    """The supported types of key usages"""

    digital_signature = "digitalSignature"
    non_repudiation = "nonRepudiation"
    key_encipherment = "keyEncipherment"
    data_encipherment = "dataEncipherment"
    key_agreement = "keyAgreement"
    key_cert_sign = "keyCertSign"
    crl_sign = "cRLSign"
    encipher_only = "encipherOnly"
    decipher_only = "decipherOnly"
```
### JS/TS
```ts
export type KeyUsageType =
  | "digitalSignature"
  | "nonRepudiation"
  | "keyEncipherment"
  | "dataEncipherment"
  | "keyAgreement"
  | "keyCertSign"
  | "cRLSign"
  | "encipherOnly"
  | "decipherOnly";
```


## CertificatePolicyAction
### .NET
```c#
public struct CertificatePolicyAction : IEquatable<CertificatePolicyAction> {
    public static final CertificatePolicyAction EMAIL_CONTACTS = fromString("EmailContacts");
    public static final CertificatePolicyAction AUTO_RENEW = fromString("AutoRenew");
    public static CertificatePolicyAction fromString(String name) {}
    public static Collection<CertificatePolicyAction> values() {}
}
```

### Java
```java
public enum CertificatePolicyAction {
    EMAIL_CONTACTS("EmailContacts"),
    AUTO_RENEW("AutoRenew");
    public static CertificatePolicyAction fromString(String value) {}
    public String toString() {}
}
```

### Python
```python
class CertificatePolicyAction(str, Enum):
    """The supported action types for the lifetime of a certificate"""

    email_contacts = "EmailContacts"
    auto_renew = "AutoRenew"
```
### JS/TS
```ts
export type CertificatePolicyAction = "EmailContacts" | "AutoRenew";
```


## LifeTimeAction
### .NET
```c#
public class LifetimeAction : IJsonSerializable, IJsonDeserializable {
    public LifetimeAction();
    public CertificatePolicyAction Action { get; set; }
    public int? DaysBeforeExpiry { get; set; }
    public int? LifetimePercentage { get; set; }
}
```

### Java
```java
public final class LifetimeAction {
    public LifetimeAction(CertificatePolicyAction action)
    public Integer getLifetimePercentage()
    public LifetimeAction setLifetimePercentage(Integer lifetimePercentage)
    public Integer getDaysBeforeExpiry()
    public LifetimeAction setDaysBeforeExpiry(Integer daysBeforeExpiry)
    public CertificatePolicyAction getAction()
}
```

### Python
```python
def __init__(self, action, lifetime_percentage=None, days_before_expiry=None):
    # type: (CertificatePolicyAction, Optional[int], Optional[int]) -> None
    @property
    def lifetime_percentage(self):
        # type: () -> int
    @property
    def days_before_expiry(self):
        # type: () -> int
    @property
    def action(self):
        # type: () -> CertificatePolicyAction
```
### JS/TS
```ts
export interface LifetimeAction {
  lifetimePercentage?: number;
  daysBeforeExpiry?: number;
  action?: CertificatePolicyAction;
}
```


## SubjectAlternativeNames
### .NET
```c#
public class SubjectAlternativeNames : {
    public SubjectAlternativeNames();
    public IList<string> DnsNames { get; }
    public IList<string> Emails { get; }
    public IList<string> UserPrincipalNames { get; }
}
```

### Java
```java
public final class SubjectAlternativeNames {
    public List<String> getEmails()
    public SubjectAlternativeNames setEmails(List<String> emails)
    public List<String> getDnsNames()
    public SubjectAlternativeNames setDnsNames(List<String> dnsNames)
    public List<String> getUserPrincipalNames()
    public SubjectAlternativeNames setUserPrincipalNames(List<String> userPrincipalNames)
}
```

### Python
N/A
### JS/TS
```ts
export type ArrayOneOrMore<T> = {
  0: T;
} & Array<T>;

export interface SubjectAlternativeNamesAll {
  emails: ArrayOneOrMore<string>;
  dnsNames: ArrayOneOrMore<string>;
  userPrincipalNames: ArrayOneOrMore<string>;
}

export type SubjectAlternativeNames = RequireAtLeastOne<SubjectAlternativeNamesAll>;
```


## CertificateKeyCurveName
### .NET
```c#
public struct CertificateKeyCurveName : IEquatable<CertificateKeyCurveName> {
    public CertificateKeyCurveName(string value);
    public static CertificateKeyCurveName P256 { get; }
    public static CertificateKeyCurveName P256K { get; }
    public static CertificateKeyCurveName P384 { get; }
    public static CertificateKeyCurveName P521 { get; }
    public static bool operator ==(CertificateKeyCurveName left, CertificateKeyCurveName right);
    public static implicit operator CertificateKeyCurveName(string value);
    public static bool operator !=(CertificateKeyCurveName left, CertificateKeyCurveName right);
    public bool Equals(CertificateKeyCurveName other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateKeyCurveName extends ExpandableStringEnum<CertificateKeyCurveName> {
    public static final CertificateKeyCurveName P_256 = fromString("P-256");
    public static final CertificateKeyCurveName P_384 = fromString("P-384");
    public static final CertificateKeyCurveName P_521 = fromString("P-521");
    public static final CertificateKeyCurveName P_256K = fromString("P-256K");
    public static CertificateKeyCurveName fromString(String name) {}
    public static Collection<CertificateKeyCurveName> values() {}
}
```

### Python
```python
# Not going to change the _k -> k bc keys are like this and they're GA
class KeyCurveName(str, Enum):
    """Supported elliptic curves"""

    p_256 = "P-256"  #: The NIST P-256 elliptic curve, AKA SECG curve SECP256R1.
    p_384 = "P-384"  #: The NIST P-384 elliptic curve, AKA SECG curve SECP384R1.
    p_521 = "P-521"  #: The NIST P-521 elliptic curve, AKA SECG curve SECP521R1.
    p_256_k = "P-256K"  #: The SECG SECP256K1 elliptic curve.
```
### JS/TS
```ts
export type CertificateKeyCurveName = "P-256" | "P-384" | "P-521" | "P-256K";
```


## CertificateKeyType
### .NET
```c#
public struct CertificateKeyType : IEquatable<CertificateKeyType> {
    public CertificateKeyType(string value);
    public static CertificateKeyType Ec { get; }
    public static CertificateKeyType EcHsm { get; }
    public static CertificateKeyType Rsa { get; }
    public static CertificateKeyType RsaHsm { get; }
    public static bool operator ==(CertificateKeyType left, CertificateKeyType right);
    public static implicit operator CertificateKeyType(string value);
    public static bool operator !=(CertificateKeyType left, CertificateKeyType right);
    public bool Equals(CertificateKeyType other);
    public override bool Equals(object obj);
    public override int GetHashCode();
    public override string ToString();
}
```

### Java
```java
public final class CertificateKeyType extends ExpandableStringEnum<CertificateKeyType> {
    public static final CertificateKeyType EC = fromString("EC");
    public static final CertificateKeyType EC_HSM = fromString("EC-HSM");
    public static final CertificateKeyType RSA = fromString("RSA");
    public static final CertificateKeyType RSA_HSM = fromString("RSA-HSM");
    public static CertificateKeyType fromString(String name) {}
    public static Collection<CertificateKeyType> values() {}
}
```

### Python
```python
class KeyType(str, Enum):
    """Supported key types"""

    ec = "EC"  #: Elliptic Curve
    ec_hsm = "EC-HSM"  #: Elliptic Curve with a private key which is not exportable from the HSM
    rsa = "RSA"  #: RSA (https://tools.ietf.org/html/rfc3447)
    rsa_hsm = "RSA-HSM"  #: RSA with a private key which is not exportable from the HSM
```
### JS/TS
```ts
export type CertificateKeyType = "EC" | "EC-HSM" | "RSA" | "RSA-HSM";
```

## MergeCertificateOptions
### .NET
```c#
public class MergeCertificateOptions : IJsonSerializable {
    public MergeCertificateOptions(string name, IEnumerable<byte[]> x509Certificates);
    public bool? Enabled { get; set; }
    public string Name { get; }
    public IDictionary<string, string> Tags { get; }
    public IEnumerable<byte[]> X509Certificates { get; }
}
```

### Java
```java
public class MergeCertificateOptions {
    public MergeCertificateOptions(String certificateName, List<byte[]> x509Certificates)
    public MergeCertificateOptions setTags(Map<String, String> tags)
    public Map<String, String> getTags()
    public MergeCertificateOptions setEnabled(Boolean enabled)
    public Boolean isEnabled()
    public String getName()
    public List<byte[]> getX509Certificates()
}
```

### Python
```python
N/A
```
### JS/TS
```ts
export interface MergeCertificateOptions extends coreHttp.OperationOptions {}
```


## ImportCertificateOptions
### .NET
```c#
public class ImportCertificateOptions : IJsonSerializable {
    public ImportCertificateOptions(string name, byte[] value);
    public byte[] Certificate { get; }
    public bool? Enabled { get; set; }
    public string Name { get; }
    public string Password { get; set; }
    public CertificatePolicy Policy { get; set; }
    public IDictionary<string, string> Tags { get; }
}
```

### Java
```java
public final class ImportCertificateOptions {
    public ImportCertificateOptions(String name, byte[] certificate)
    public ImportCertificateOptions setEnabled(Boolean enabled)
    public Boolean isEnabled()
    public CertificatePolicy getCertificatePolicy()
    public ImportCertificateOptions setCertificatePolicy(CertificatePolicy certificatePolicy)
    public ImportCertificateOptions setTags(Map<String, String> tags)
    public Map<String, String> getTags()
    public ImportCertificateOptions setPassword(String password)
    public String getPassword()
    public String getName()
    public byte[] getCertificate()
}
```

### Python
```python
N/A
```
### JS/TS
```ts
export interface ImportCertificateOptions extends coreHttp.OperationOptions {
  enabled?: boolean;
  password?: string;
  policy?: CertificatePolicy;
  tags?: CertificateTags;
```


## WellKnownIssuerNames
### .NET
```c#
public static class WellKnownIssuerNames {
    public const string Self = "Self";
    public const string Unknown = "Unknown";
}
```

### Java
```java
public class WellKnownIssuerNames {
    public static final String SELF = "Self";
    public static final String UNKNOWN = "Unknown";
}
```

### Python
```python
class WellKnownIssuerNames(str, Enum):
    """Collection of well-known issuer names"""

    self = "Self"  #: Use this issuer for a self-signed certificate
    unknown = "Unknown"
```
### JS/TS
```ts
export enum WellKnownIssuerNames {
  Self = "Self",
  Unknown = "Unknown"
}
```



## AdministratorContact
### .NET
```c#
public class AdministratorContact {
    public AdministratorContact();
    public string Email { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Phone { get; set; }
}
```

### Java
```java
public final class AdministratorContact {
    public AdministratorContact(String firstName, String lastName, String email)
    public AdministratorContact(String firstName, String lastName, String email, String phone)
    public String getFirstName()
    public String getLastName()
    public String getEmail()
    public String getPhone()
}
```

### Python
```python
def __init__(self, first_name=None, last_name=None, email=None, phone=None):
        # type: (Optional[str], Optional[str], Optional[str], Optional[str]) -> None

@property
    def email(self):
        # type: () -> str
    @property
    def first_name(self):
        # type: () -> str
    @property
    def last_name(self):
        # type: () -> str
    @property
    def phone(self):
        # type: () -> str
```
### JS/TS
```ts
export interface AdministratorContact {
  firstName?: string;
  lastName?: string;
  email?: string;
  phone?: string;
}
```


## CertificateContact
### .NET
```c#
public class CertificateContact : IJsonDeserializable, IJsonSerializable {
    public CertificateContact();
    public string Email { get; set; }
    public string Name { get; set; }
    public string Phone { get; set; }
}
```

### Java
```java
public final class CertificateContact {
    public CertificateContact(String name, String email, String phone)
    public CertificateContact(String name, String email)
    public String getEmail()
    public String getName()
    public String getPhone()
}
```

### Python
```python
def __init__(self, email=None, name=None, phone=None):
        # type: (Optional[str], Optional[str], Optional[str]) -> None
@property
    def email(self):
        # type: () -> str
    @property
    def name(self):
        # type: () -> str
    @property
    def phone(self):
        # type: () -> str
```
### JS/TS
```ts
export interface CertificateContactAll {
  email: string;
  name: string;
  phone: string;
}

export type RequireAtLeastOne<T> = {
  [K in keyof T]-?: Required<Pick<T, K>> & Partial<Pick<T, Exclude<keyof T, K>>>;
}[keyof T];

export type CertificateContact = RequireAtLeastOne<CertificateContactAll> | undefined;
```

## CertificateIssuer
### .NET
```c#
public class CertificateIssuer : IJsonDeserializable, IJsonSerializable {
    public CertificateIssuer(string name);
    public string AccountId { get; set; }
    public IList<AdministratorContact> AdministratorContacts { get; }
    public DateTimeOffset? CreatedOn { get; }
    public bool? Enabled { get; set; }
    public Uri Id { get; }
    public string Name { get; }
    public string OrganizationId { get; set; }
    public string Password { get; set; }
    public string Provider { get; }
    public IssuerProperties Properties { get; }
    public DateTimeOffset? UpdatedOn { get; }
}
```

### Java
```java
public final class CertificateIssuer {
    public CertificateIssuer(String name, String provider)
    public String getId()
    public String getProvider()
    public String getName()
    public String getAccountId()
    public CertificateIssuer setAccountId(String accountId)
    public String getPassword()
    public CertificateIssuer setPassword(String password)
    public String getOrganizationId()
    public CertificateIssuer setOrganizationId(String organizationId)
    public List<AdministratorContact> getAdministratorContacts()
    public CertificateIssuer setAdministratorContacts(List<AdministratorContact> administratorContacts)
    public Boolean isEnabled()
    public CertificateIssuer setEnabled(Boolean enabled)
    public OffsetDateTime getCreatedOn()
    public OffsetDateTime getUpdatedOn()
}
```

### Python
```python
def __init__(
        self,
        provider=None,  # type: Optional[str]
        attributes=None,  # type: Optional[models.IssuerAttributes]
        account_id=None,  # type: Optional[str]
        password=None,  # type: Optional[str]
        organization_id=None,  # type: Optional[str]
        admin_contacts=None,  # type: Optional[List[AdministratorContact]]
        **kwargs  # type: Any
    ):
@property
    def id(self):
        # type: () -> str
    @property
    def name(self):
        # type: () -> str
    @property
    def vault_url(self):
        # type: () -> str
    @property
    def provider(self):
        # type: () -> str
    @property
    def enabled(self):
        # type: () -> bool
    @property
    def created_on(self):
        # type: () -> datetime
    @property
    def updated_on(self):
        # type: () -> datetime
    @property
    def account_id(self):
        # type: () -> str
    @property
    def password(self):
        # type: () -> str
    @property
    def organization_id(self):
        # type: () -> str
    @property
    def admin_contacts(self):
        # type: () -> List[AdministratorContact]
```
### JS/TS
```ts
export interface CertificateIssuer {
  id?: string;
  enabled?: boolean;
  readonly createdOn?: Date;
  readonly updatedOn?: Date;
  readonly name?: string;
  accountId?: string;
  password?: string;
  organizationId?: string;
  administratorContacts?: AdministratorContact[];
  properties?: IssuerProperties;
}
```

## IssuerProperties
### .NET
```c#
public class IssuerProperties : IJsonDeserializable, IJsonSerializable {
    public Uri Id { get; }
    public string Name { get; }
    public string Provider { get; set; }
}
```

### Java
```java
public class IssuerProperties {
    IssuerProperties(String name, String provider)
    public String getId()
    public String getProvider()
    public String getName()
}
```

### Python
```python
def __init__(self, provider=None, **kwargs):
        # type: (Optional[str], **Any) -> None
@property
    def id(self):
        # type: () -> str
    @property
    def name(self):
        # type: () -> str
    @property
    def provider(self):
        # type: () -> str
    @property
    def vault_url(self):
        # type: () -> str
```
### JS/TS
```ts
export interface IssuerProperties {
  id?: string;
  readonly name?: string;
  provider?: string;
}
```

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign4.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign5.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign6.png)
