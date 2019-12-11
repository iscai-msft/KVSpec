# Azure KeyVault Certificates API Design

Azure Key Vault is a cloud service that provides secure storage and automated management of certificates used throughout a cloud application. Multiple certificate, and multiple versions of the same certificate, can be kept in the Key Vault. Each certificate in the vault has a policy associated with it which controls the issuance and lifetime of the certificate, along with actions to be taken as certificates near expiry.

The Azure Key Vault Certificate client library enables programmatically managing certificates, offering methods to create, update, list, and delete certificates, policies, issuers, and contacts. The library also supports managing pending certificate operations and management of deleted certificates.

## Concepts
* Certificate
* Certificate Policy
* Issuer
* Contact
* Certificate Operation


## Scenario - Create Certificate
### Usage


### Java
```java
// Async Example
CertificateClientBuilder builder = new CertificateClientBuilder()
        .endpoint(<your-vault-url>)
        .credential(new DefaultAzureCredentialBuilder().build());

CertificateClient certificateClient = builder.buildClient();
CertificateAsyncClient certificateAsyncClient = builder.buildAsyncClient();

CertificatePolicy policy = new CertificatePolicy("Self", "CN=SelfSignedJavaPkcs12")
                                .setValidityInMonths(24)
                                .subjectAlternativeNames(SubjectAlternativeNames.fromEmails(Arrays.asList("wow@gmail.com")));

//Creates a certificate and polls on its progress.
Poller<CertificateOperation, Certificate> createCertPoller = certificateAsyncClient.createCertificate("certificateName", policy);

createCertPoller
    .getObserver()
    .subscribe(pollResponse -> {
        System.out.println("---------------------------------------------------------------------------------");
        System.out.println(pollResponse.getStatus());
        System.out.println(pollResponse.getValue().status());
        System.out.println(pollResponse.getValue().statusDetails());
    });

    // Do other ops ....
    // Cannot move forward without cert at this point
    Mono<Certificate> certificate = createCertPoller.block();


// Sync example
// Blocks until the cert is created.
Certificate myCertificate = certificateClient.createCertificate(String name);

//By default blocks until certificate is created, unless a timeout is specified as an optional parameter.
try {
    myCertificate = certificateClient.createCertificate("certificateName",
    policy, Duration.ofSeconds(60));
} catch (IllegalStateException e) {
    // Certificate wasn't created in the specified duration.
    // Log / Handle here
}
```

### .NET
```c#

var client = new CertificateClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

// Let's create a self signed certifiate using the default policy. If the certificiate
// already exists in the Key Vault, then a new version of the key is created.
string certName = $"defaultCert-{Guid.NewGuid()}";

CertificateOperation certOp = await client.StartCreateCertificateAsync(certName);

// Next let's wait on the certificate operation to complete. Note that certificate creation can last an indeterministic
// amount of time, so applications should only wait on the operation to complete in the case the issuance time is well
// known and within the scope of the application lifetime. In this case we are creating a self-signed certificate which
// should be issued in a relatively short amount of time.
CertificateWithPolicy certificate = await certOp.WaitCompletionAsync();

// At some time later we could get the created certificate along with it's policy from the Key Vault.
certificate = await client.GetCertificateWithPolicyAsync(certName);

Debug.WriteLine($"Certificate was returned with name {certificate.Name} which expires {certificate.Properties.Expires}");


// Create Cert Synchronously
CertificateOperation certOp = client.StartCreateCertificate(certName);

// Next let's wait on the certificate operation to complete. Note that certificate creation can last an indeterministic
// amount of time, so applications should only wait on the operation to complete in the case the issuance time is well
// known and within the scope of the application lifetime. In this case we are creating a self-signed certificate which
// should be issued in a relatively short amount of time.
while (!certOp.HasCompleted)
{
    certOp.UpdateStatus();

    Thread.Sleep(certOp.PollingInterval);
}

// Let's get the created certificate along with it's policy from the Key Vault.
CertificateWithPolicy certificate = client.GetCertificateWithPolicy(certName);

Debug.WriteLine($"Certificate was returned with name {certificate.Name} which expires {certificate.Properties.Expires}");
```

### Python
```python
    credential = DefaultAzureCredential()
    client = CertificateClient(vault_url=VAULT_URL, credential=credential)
    try:
        # Alternatively, if you would like to use our default policy, don't pass a policy parameter to
        # our certificate creation method
        cert_policy = CertificatePolicy(content_type=SecretContentType.PKCS12,
                                        issuer_name='Self',
                                        subject_name='CN=*.microsoft.com',
                                        validity_in_months=24,
                                        san_dns_names=['sdk.azure-int.net']
                                        )
        cert_name = "HelloWorldCertificate"

        # create_certificate returns a poller. Awaiting the poller will return the certificate
        # if creation is successful, and the CertificateOperation if not.
        create_certificate_poller = await client.create_certificate(name=cert_name, policy=cert_policy)
        certificate = await create_certificate_poller
        print("Certificate with name '{0}' created".format(certificate.name))


        # Creating cert synchronously
        # create_certificate returns a poller. Calling result() on the poller will return the certificate
        # if creation is successful, and the CertificateOperation if not. The wait() call on the poller will
        # wait until the long running operation is complete.
        certificate = client.create_certificate(name=cert_name, policy=cert_policy).result()
        print("Certificate with name '{0}' created".format(certificate.name))

    except HttpResponseError as e:
    print("\nrun_sample has caught an error. {0}".format(e.message))

    finally:
        print("\nrun_sample done")
```
### JS/TS
```ts
  const client = new CertificatesClient(url, credential);

  // Creating a self-signed certificate
  const certificate = await client.createCertificate("MyCertificate", {
    issuerParameters: { name: "Self" },
    x509CertificateProperties: { subject: "cn=MyCert" }
  });

  console.log("Certificate: ", certificate);
```

### API
### Java
```java
Poller<CertificateOperation, Certificate> createCertificate(String name);
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy);
Poller<CertificateOperation, Certificate> createCertificate(String name, CertificatePolicy policy, boolean enabled, Map<String, String> tags);

public PollerFlux<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy, boolean isEnabled, Map<String, String> tags)
public PollerFlux<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy)

public SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy, Boolean isEnabled, Map<String, String> tags)
public SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> beginCreateCertificate(String certificateName, CertificatePolicy policy)
```

### .NET
```c#
public virtual CertificateOperation StartCreateCertificate(string name, CancellationToken cancellationToken = default);
public virtual CertificateOperation StartCreateCertificate(string name, CertificatePolicy policy, bool? enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default);

public virtual async Task<CertificateOperation> StartCreateCertificateAsync(string name, CancellationToken cancellationToken = default);
public virtual async Task<CertificateOperation> StartCreateCertificateAsync(string name, CertificatePolicy policy, bool? enabled = default, IDictionary<string, string> tags = default, CancellationToken cancellationToken = default)

```
### Python
```python
    def create_certificate(
            self,
            name,  # type: str
            policy=None,  # type: Optional[CertificatePolicy]
            enabled=None,  # type: Optional[bool]
            tags=None,  # type: Optional[Dict[str, str]]
            **kwargs  # type: Any
    )
```
### JS/TS
```ts
  public async createCertificate(
    name: string,
    certificatePolicy: CertificatePolicy,
    enabled?: boolean,
    tags?: CertificateTags,
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - Get Certificate
### Usage
### Java
```java
//Retrieve asynchronously
certificateAsyncClient.getCertificate("certificateName", "certificateVersion")
    .subscribe(certificateResponse ->
        System.out.printf("Certificate is returned with name %s and secretId %s %n", certificateResponse.name(),
            certificateResponse.secretId()));

// Retrieve synchronously
Certificate certificate = certificateClient.getCertificateWithPolicy("certificateName");
System.out.printf("Recevied certificate with name %s and version %s and secret id", certificate.name(),
    certificate.version(), certificate.secretId());
```

### Python
```python
//Async
# Let's get the bank certificate using its name
print("\n.. Get a Certificate by name")
bank_certificate = await client.get_certificate_with_policy(name=cert_name)
print("Certificate with name '{0}' was found.".format(bank_certificate.name))

//Sync
# Let's get the bank certificate using its name
print("\n.. Get a Certificate by name")
bank_certificate = client.get_certificate_with_policy(name=cert_name)
print("Certificate with name '{0}' was found'.".format(bank_certificate.name))
```

### API
### Java
```java
// Async API
public Mono<KeyVaultCertificateWithPolicy> getCertificate(String certificateName)
public Mono<Response<KeyVaultCertificateWithPolicy>> getCertificateWithResponse(String certificateName)
public Mono<Response<KeyVaultCertificate>> getCertificateVersionWithResponse(String name, String version) {}
public Mono<KeyVaultCertificate> getCertificateVersion(String name, String version) {}

//Sync API
public KeyVaultCertificateWithPolicy getCertificate(String certificateName)
public Response<KeyVaultCertificateWithPolicy> getCertificateWithResponse(String certificateName)
public Response<KeyVaultCertificate> getCertificateVersionWithResponse(String certificateName, String version, Context context)
public KeyVaultCertificate getCertificateVersion(String certificateName, String version)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> GetCertificateWithPolicy(string name, CancellationToken cancellationToken = default);
public virtual async Task<Response<CertificateWithPolicy>> GetCertificateWithPolicyAsync(string name, CancellationToken cancellationToken = default);
public virtual Response<Certificate> GetCertificate(string name, string version, CancellationToken cancellationToken = default);
public virtual async Task<Response<Certificate>> GetCertificateAsync(string name, string version, CancellationToken cancellationToken = default)
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
    name: string,
    version: string,
    options?: RequestOptionsBase
  ): Promise<Certificate>

    public async getCertificateWithPolicy(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateWithPolicy>
```

## Scenario - Get Certificate Policy

### Usage
### Java
```java
//Async
certificateAsyncClient.getCertificatePolicy("certificateName")
    .subscribe(policy ->
        System.out.printf("Certificate policy is returned with issuer name %s and subject name %s %n",
            policy.issuerName(), policy.subjectName()));

//Sync
CertificatePolicy policy = certificateClient.getCertificatePolicy("certificateName");
System.out.printf("Received policy with subject name %s", policy.subjectName());
```

### JS/TS
```ts
const policy = await client.getCertificatePolicy("MyCertificate");
console.log(policy);
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
public virtual Response<CertificatePolicy> GetCertificatePolicy(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificatePolicy>> GetCertificatePolicyAsync(string certificateName, CancellationToken cancellationToken = default)

```
### Python
```python
async def get_certificate_policy(self, certificate_name: str, **kwargs: "Any") -> CertificatePolicy:
```

### JS/TS
```ts
  public async getCertificatePolicy(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificatePolicy>
```

## Scenario - Update Certificate
Question: Updating Certificate via Properties vs setting fields.

### Usage
### Java
```java

//Async
certificateAsyncClient.getCertificateWithPolicy("certificateName")
    .subscribe(certificateResponseValue -> {
        CertificateProperties certificateProps = certificateResponseValue.getProperties();
        //Update enabled status of the certificate
        certificateProps.setEnabled(false);
        certificateAsyncClient.updateCertificateProperties(certificateProps)
            .subscribe(certificateResponse ->
                System.out.printf("Certificate's enabled status %s %n",
                    certificateResponse.getProperties().getEnabled().toString()));
    });

//Sync
CertificateProperties certProps = certificateClient.getCertificateWithPolicy("certificateName").getProperties();
Map<String, String> tags = new HashMap<>();
tags.put("foo", "bar");
// Update certificate enabled status and tags
certProps.setEnabled(false);
certProps.setTags(tags);
Certificate updatedCertificate = certificateClient.updateCertificateProperties(certProps);
System.out.printf("Updated Certificate with name %s and enabled status %s", updatedCertificate.name(),
    updatedCertificate.getProperties().getEnabled());
```

### NET
```c#
//Async
CertificateProperties certificateProperties = certificate.Properties;
certificateProperties.Enabled = false;

Certificate updatedCert = await client.UpdateCertificatePropertiesAsync(certificateProperties);

Debug.WriteLine($"Certificate enabled set to '{updatedCert.Properties.Enabled}'");


//Sync
CertificateProperties certificateProperties = certificate.Properties;
certificateProperties.Enabled = false;

Certificate updatedCert = client.UpdateCertificateProperties(certificateProperties);

Debug.WriteLine($"Certificate enabled set to '{updatedCert.Properties.Enabled}'");
```
### Python
```python

//Async
print("\n.. Update a Certificate by name")
tags = {"a": "b"}
updated_certificate = await client.update_certificate_properties(name=bank_certificate.name, tags=tags)
print("Certificate with name '{0}' was updated on date '{1}'".format(
    bank_certificate.name,
    updated_certificate.properties.updated)
)
print("Certificate with name '{0}' was updated with tags '{1}'".format(
    bank_certificate.name,
    updated_certificate.properties.tags)
)

//Sync
print("\n.. Update a Certificate by name")
tags = {"a": "b"}
updated_certificate = client.update_certificate_properties(name=bank_certificate.name, tags=tags)
print("Certificate with name '{0}' was updated on date '{1}'".format(
    bank_certificate.name,
    updated_certificate.properties.updated)
)
print("Certificate with name '{0}' was updated with tags '{1}'".format(
    bank_certificate.name,
    updated_certificate.properties.tags)
)
```

### JS/TS
```ts
await client.updateCertificate("MyCertificate", "", {
   tags: {
    customTag: "value"
   }
});
```

### API
### Java
```java

public Mono<KeyVaultCertificate> updateCertificateProperties(CertificateProperties certificateProperties)
public Mono<Response<KeyVaultCertificate>> updateCertificatePropertiesWithResponse(CertificateProperties certificateProperties)


public KeyVaultCertificate updateCertificateProperties(CertificateProperties certificateProperties)
public Response<KeyVaultCertificate> updateCertificatePropertiesWithResponse(CertificateProperties certificateProperties, Context context)
```

### .NET
```c#
public virtual Response<Certificate> UpdateCertificateProperties(CertificateProperties certificateProperties, CancellationToken cancellationToken = default);

public virtual async Task<Response<Certificate>> UpdateCertificatePropertiesAsync(CertificateProperties certificateProperties, CancellationToken cancellationToken = default);
```

### Python
```python
async def update_certificate_properties(
        self, certificate_name: str, version: Optional[str] = None, **kwargs: "Any"
    ) -> KeyVaultCertificate:
```

### JS/TS
```ts
  public async updateCertificateProperties(
    name: string,
    version: string,
    options?: KeyVaultClientUpdateCertificateOptionalParams
  ): Promise<Certificate>
```

## Scenario - Update Certificate Policy
### Usage
### Java
```java
//Async
certificateAsyncClient.getCertificatePolicy("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificatePolicyResponseValue -> {
        CertificatePolicy certificatePolicy = certificatePolicyResponseValue;
        // Update validity
        certificatePolicy.setValidityInMonths(24);
        certificateAsyncClient.updateCertificatePolicy("certificateName", certificatePolicy)
            .subscribe(updatedPolicy ->
                System.out.printf("Certificate policy's updated validity %d %n",
                    updatedPolicy.getValidityInMonths()));
    });

// Sync
CertificatePolicy certificatePolicy = certificateClient.getCertificatePolicy("certificateName");
// Update the certificate policy cert transparency property.
certificatePolicy.setValidityInMonths(24);
CertificatePolicy updatedCertPolicy = certificateClient.updateCertificatePolicy("certificateName",
    certificatePolicy);
System.out.printf("Updated Certificate Policy validity %d", updatedCertPolicy.getValidityInMonths());
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
public virtual Response<CertificatePolicy> UpdateCertificatePolicy(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificatePolicy>> UpdateCertificatePolicyAsync(string certificateName, CertificatePolicy policy, CancellationToken cancellationToken = default)


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
    name: string,
    policy: CertificatePolicy,
    options?: RequestOptionsBase
  ): Promise<CertificatePolicy>
```


## Scenario - Delete Certificate

### Usage

### .NET
```c#
//Async
await client.DeleteCertificateAsync(certName);

//Sync
client.DeleteCertificate(certName);
```

### python
``` python
# Async
print("\n.. Delete Certificate")
deleted_certificate = await client.delete_certificate(name=bank_certificate.name)
print("Deleting Certificate..")
print("Certificate with name '{0}' was deleted.".format(deleted_certificate.name))


# Sync
print("\n.. Delete Certificate")
deleted_certificate = client.delete_certificate(name=bank_certificate.name)
print("Deleting Certificate..")
print("Certificate with name '{0}' was deleted.".format(deleted_certificate.name))
```

### API
### Java
```java
public PollerFlux<DeletedCertificate, Void> beginDeleteCertificate(String certificateName)

public SyncPoller<DeletedCertificate, Void> beginDeleteCertificate(String certificateName)
```

### .NET
```c#
public virtual Response<DeletedCertificate> DeleteCertificate(string name, CancellationToken cancellationToken = default);
public virtual async Task<Response<DeletedCertificate>> DeleteCertificateAsync(string name, CancellationToken cancellationToken = default);


```
### Python
```python
async def delete_certificate(self, certificate_name: str, **kwargs: "Any") -> DeletedCertificate:
```

```
### JS/TS
```ts
  public async deleteCertificate(
    certificateName: string,
    options?: RequestOptionsBase
  ): Promise<DeletedCertificate>
```

## Scenario - Get Deleted Certificate
### Usage

### Java
```java
//Async
certificateAsyncClient.getDeletedCertificate("certificateName")
    .subscribe(deletedSecretResponse ->
        System.out.printf("Deleted Certificate's Recovery Id %s %n", deletedSecretResponse.recoveryId()));

//Sync
DeletedCertificate deletedCertificate = certificateClient.getDeletedCertificate("certificateName");
System.out.printf("Deleted certificate with name %s and recovery id %s", deletedCertificate.name(),
    deletedCertificate.recoveryId());
```
### JS/TS
 ```ts
client.getDeletedCertificate("MyDeletedCertificate");
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
public virtual Response<DeletedCertificate> GetDeletedCertificate(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<DeletedCertificate>> GetDeletedCertificateAsync(string name, CancellationToken cancellationToken = default)


```
### Python
```python
async def get_deleted_certificate(self, certificate_name: str, **kwargs: "Any") -> DeletedCertificate:
```
### JS/TS
```ts
  public async getDeletedCertificate(
    name: string,
    options?: RequestOptionsBase
  ): Promise<DeletedCertificate>
```

## Scenario - Recover Deleted Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.recoverDeletedCertificate("deletedCertificateName")
    .subscribe(recoveredCert ->
        System.out.printf("Recovered Certificate with name %s %n", recoveredCert.name()));

//Sync
Certificate certificate = certificateClient.recoverDeletedCertificate("deletedCertificateName");
System.out.printf(" Recovered Deleted certificate with name %s and id %s", certificate.name(),
    certificate.id());
```
### JS/TS
 ```ts
await client.recoverDeletedCertificate("MyCertificate")
```

### API
### Java
```java
public PollerFlux<KeyVaultCertificateWithPolicy, Void> beginRecoverDeletedCertificate(String certificateName)

public SyncPoller<KeyVaultCertificateWithPolicy, Void> beginRecoverDeletedCertificate(String certificateName)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> RecoverDeletedCertificate(string name, CancellationToken cancellationToken = default);
public virtual async Task<Response<CertificateWithPolicy>> RecoverDeletedCertificateAsync(string name, CancellationToken cancellationToken = default);
```
### Python
```python
async def recover_deleted_certificate(self, certificate_name: str, **kwargs: "Any") -> KeyVaultCertificate:
```
//Sync
```python
def begin_recover_deleted_certificate(self, certificate_name, **kwargs) -> LROPoller[KeyVaultCertificate]
```
### JS/TS
```ts
  public async recoverDeletedCertificate(
    name: string,
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - Purge Delete Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.purgeDeletedCertificate("deletedCertificateName")
    .doOnSuccess(response -> System.out.println("Successfully Purged certificate"));

//Sync
certificateClient.purgeDeletedCertificate("certificateName");
```
### python
 ```python

# async
print("\n.. Purge Deleted Certificate")
await client.purge_deleted_certificate(name=storage_cert_name)
print("Certificate has been permanently deleted.")

# sync
print("\n.. Purge Deleted Certificate")
client.purge_deleted_certificate(name=storage_cert_name)
print("Certificate has been permanently deleted.")
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
public virtual Response PurgeDeletedCertificate(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response> PurgeDeletedCertificateAsync(string name, CancellationToken cancellationToken = default)

```
### Python
```python
async def purge_deleted_certificate(self, certificate_name: str, **kwargs: "Any") -> None:
```
### JS/TS
```ts
public async purgeDeletedCertificate(name: string, options?: RequestOptionsBase): Promise<null>
```

## Scenario - Backup Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.backupCertificate("certificateName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateBackupResponse ->
        System.out.printf("Certificate's Backup Byte array's length %s %n", certificateBackupResponse.length));

//Sync
byte[] certificateBackup = certificateClient.backupCertificate("certificateName");
System.out.printf("Backed up certificate with back up blob length %d", certificateBackup.length);
```

### python
 ```python

# async
print("\n.. Create a backup for an existing certificate")
certificate_backup = await client.backup_certificate(name=cert_name)
print("Backup created for certificate with name '{0}'.".format(cert_name))

# sync
print("\n.. Create a backup for an existing certificate")
certificate_backup = client.backup_certificate(name=cert_name)
print("Backup created for certificate with name '{0}'.".format(cert_name))
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
public virtual Response<byte[]> BackupCertificate(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<byte[]>> BackupCertificateAsync(string name, CancellationToken cancellationToken = default)
```
### Python
```python
async def backup_certificate(self, certificate_name: str, **kwargs: "Any") -> bytes:
```
### JS/TS
```ts
  public async backupCertificate(
    name: string,
    options?: RequestOptionsBase
  ): Promise<BackupCertificateResult>
```

## Scenario - Restore Certificate
### Usage
### Java
```java
//Async
certificateAsyncClient.restoreCertificate(certificateBackupByteArray)
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(certificateResponse -> System.out.printf("Restored Certificate with name %s and key id %s %n",
        certificateResponse.name(), certificateResponse.keyId()));

//Sync
byte[] certificateBackupBlob = {};
Certificate certificate = certificateClient.restoreCertificate(certificateBackupBlob);
System.out.printf(" Restored certificate with name %s and id %s", certificate.name(), certificate.id());
```

### python
 ```python

# async
print("\n.. Restore the certificate using the backed up certificate bytes")
certificate = await client.restore_certificate(certificate_backup)
print("Restored Certificate with name '{0}'".format(certificate.name))

# sync
print("\n.. Restore the certificate from the backup")
certificate = client.restore_certificate(certificate_backup)
print("Restored Certificate with name '{0}'".format(certificate.name))
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
public virtual Response<CertificateWithPolicy> RestoreCertificate(byte[] backup, CancellationToken cancellationToken = default);

public virtual async Task<Response<CertificateWithPolicy>> RestoreCertificateAsync(byte[] backup, CancellationToken cancellationToken = default)
```
### Python
```python
async def restore_certificate_backup(self, backup: bytes, **kwargs: "Any") -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async restoreCertificate(
    certificateBackup: Uint8Array,
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - List Ceriticates
### Usage
### .NET
```c#
//Async
// Let's list the certificates which exist in the vault along with their thumbprints
await foreach (CertificateProperties cert in client.GetCertificatesAsync())
{
    Debug.WriteLine($"Certificate is returned with name {cert.Name} and thumbprint {BitConverter.ToString(cert.X509Thumbprint)}");
}

//Sync
// Let's list the certificates which exist in the vault along with their thumbprints
foreach (CertificateProperties cert in client.GetCertificates())
{
    Debug.WriteLine($"Certificate is returned with name {cert.Name} and thumbprint {BitConverter.ToString(cert.X509Thumbprint)}");
}
```

### python
 ```python
# async
print("\n.. List certificates from the Key Vault")
certificates = client.list_certificates()
async for certificate in certificates:
    print("Certificate with name '{0}' was found.".format(certificate.name))

# sync
print("\n.. List certificates from the Key Vault")
certificates = client.list_certificates()
for certificate in certificates:
    print("Certificate with name '{0}' was found.".format(certificate.name))
```

### API
### Java
```java
public PagedFlux<CertificateProperties> listPropertiesOfCertificates(Boolean includePending)
public PagedFlux<CertificateProperties> listPropertiesOfCertificates()

public PagedIterable<CertificateProperties> listPropertiesOfCertificates()
public PagedIterable<CertificateProperties> listPropertiesOfCertificates(boolean includePending, Context context)
```

### .NET
```c#
public virtual IEnumerable<Response<CertificateProperties>> GetCertificates(bool? includePending = default, CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<CertificateProperties>> GetCertificatesAsync(bool? includePending = default, CancellationToken cancellationToken = default)
```
### Python
```python
def list_properties_of_certificates(self, **kwargs: "Any") -> AsyncIterable[CertificateProperties]:
```
### JS/TS
```ts
  public listCertificates(
    options?: RequestOptionsBase
  ): PagedAsyncIterableIterator<CertificateAttributes, CertificateAttributes[]>
```

## Scenario - List Ceriticate Versions
### Usage
### .NET
```c#
//Async
// Let's print all the versions of this certificate
await foreach (CertificateProperties cert in client.GetCertificateVersionsAsync(certName1))
{
    Debug.WriteLine($"Certificate {cert.Name} with name {cert.Version}");
}

//Sync
// Let's print all the versions of this certificate
foreach (CertificateProperties cert in client.GetCertificateVersions(certName1))
{
    Debug.WriteLine($"Certificate {cert.Name} with name {cert.Version}");
}
```

### python
 ```python
# async
print("\n.. List versions of the certificate using its name")
certificate_versions = client.list_certificate_versions(bank_cert_name)
async for certificate_version in certificate_versions:
    print("Bank Certificate with name '{0}' with version '{1}' has tags: '{2}'.".format(
        certificate_version.name,
        certificate_version.version,
        certificate_version.tags))

# sync
print("\n.. List versions of the certificate using its name")
certificate_versions = client.list_certificate_versions(bank_cert_name)
for certificate_version in certificate_versions:
    print("Bank Certificate with name '{0}' with version '{1}' has tags: '{2}'.".format(
        certificate_version.name,
        certificate_version.version,
        certificate_version.tags))
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
public virtual IEnumerable<Response<CertificateProperties>> GetCertificateVersions(string name, CancellationToken cancellationToken = default);

public virtual IAsyncEnumerable<Response<CertificateProperties>> GetCertificateVersionsAsync(string name, CancellationToken cancellationToken = default);
```
### Python
```python
def list_properties_of_certificate_versions(
        self, certificate_name: str, **kwargs: "Any"
    ) -> AsyncIterable[CertificateProperties]:
```
### JS/TS
```ts
  public listCertificateVersions(
    name: string,
    options?: RequestOptionsBase
  ): PagedAsyncIterableIterator<CertificateAttributes, CertificateAttributes[]>
```

## Scenario - List Deleted Certificates
### Usage
### .NET
```c#
//Async
// Let's print all the versions of this certificate
await foreach (CertificateProperties cert in client.GetCertificateVersionsAsync(certName1))
{
    Debug.WriteLine($"Certificate {cert.Name} with name {cert.Version}");
}

//Sync
// You can list all the deleted and non-purged certificates, assuming Key Vault is soft-delete enabled.
foreach (DeletedCertificate deletedCert in client.GetDeletedCertificates())
{
    Debug.WriteLine($"Deleted certificate's recovery Id {deletedCert.RecoveryId}");
}
```

### python
 ```python
# async
print("\n.. List deleted certificates from the Key Vault")
deleted_certificates = client.list_deleted_certificates()
async for deleted_certificate in deleted_certificates:
    print(
        "Certificate with name '{0}' has recovery id '{1}'".format(deleted_certificate.name, deleted_certificate.recovery_id)
    )

# sync
print("\n.. List deleted certificates from the Key Vault")
deleted_certificates = client.list_deleted_certificates()
for deleted_certificate in deleted_certificates:
    print("Certificate with name '{0}' has recovery id '{1}'".format(
            deleted_certificate.name,
            deleted_certificate.recovery_id))
```

### API
### Java
```java
public PagedFlux<DeletedCertificate> listDeletedCertificates()

public PagedIterable<DeletedCertificate> listDeletedCertificates()
public PagedIterable<DeletedCertificate> listDeletedCertificates(Boolean includePending, Context context)
```

### .NET
```c#
public virtual IEnumerable<Response<DeletedCertificate>> GetDeletedCertificates(CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<DeletedCertificate>> GetDeletedCertificatesAsync(CancellationToken cancellationToken = default)
```

### Python
```python
def list_deleted_certificates(self, **kwargs: "Any") -> AsyncIterable[DeletedCertificate]:
```

### JS/TS
```javascript
  public listDeletedCertificates(
    options?: KeyVaultClientGetDeletedCertificatesOptionalParams
  ): PagedAsyncIterableIterator<DeletedCertificate, DeletedCertificate[]>
```


## Scenario - Create Certificate Issuer
Discuss - Create vs Set
### Usage
### java
```java
//Async
certificateAsyncClient.createIssuer("issuerName", "providerName")
    .subscribe(issuer -> {
        System.out.printf("Issuer created with %s and %s", issuer.name(), issuer.provider());
    });

//Sync
Issuer issuerToCreate = new Issuer("myissuer", "myProvider")
    .administrators(Arrays.asList(new Administrator("test", "name", "test@example.com")));
Issuer returnedIssuer = certificateClient.createIssuer(issuerToCreate);
System.out.printf("Created Issuer with name %s provider %s", returnedIssuer.name(), returnedIssuer.provider());
```

### python
 ```python
# async
admin_details = [AdministratorDetails(
    first_name="John",
    last_name="Doe",
    email="admin@microsoft.com",
    phone="4255555555"
)]

await client.create_issuer(
    name="issuer1",
    provider="Test",
    account_id="keyvaultuser",
    admin_details=admin_details,
    enabled=True
)

# sync
# The provider for your issuer must exist for your vault location and tenant id.
client.create_issuer(
    name="issuer1",
    provider="Test",
    account_id="keyvaultuser",
    admin_details=admin_details,
    enabled=True
    )
```
### JS/TS
```ts
await client.setIssuer("IssuerName", "Provider");
```

### API
### Java
```java
public Mono<CertificateIssuer> createIssuer(String issuerName, String provider)
public Mono<CertificateIssuer> createIssuer(CertificateIssuer issuer)
public Mono<Response<CertificateIssuer>> createIssuerWithResponse(CertificateIssuer issuer)

public CertificateIssuer createIssuer(String issuerName, String provider)
public CertificateIssuer createIssuer(CertificateIssuer issuer)
public Response<CertificateIssuer> createIssuerWithResponse(CertificateIssuer issuer, Context context)
```

### .NET
```c#
public virtual Response<Issuer> CreateIssuer(Issuer issuer, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> CreateIssuerAsync(Issuer issuer, CancellationToken cancellationToken = default)
```
### Python
```python
async def create_issuer(
        self, issuer_name: str, provider: str, **kwargs: "Any"
    ) -> CertificateIssuer:
```
### JS/TS
```javascript
  public async setIssuer(
    issuerName: string,
    provider: string,
    options?: KeyVaultClientSetCertificateIssuerOptionalParams
  ): Promise<CertificateIssuer>
```

## Scenario - Get Certificate Issuer
### Usage
### java
```java
//Async
certificateAsyncClient.getIssuer("issuerName")
    .subscriberContext(Context.of(key1, value1, key2, value2))
    .subscribe(issuer -> {
        System.out.printf("Issuer returned with %s and %s", issuer.name(), issuer.provider());
    });

//Sync
Response<Issuer> issuerResponse = certificateClient.getIssuerWithResponse("issuerName",
    new Context(key1, value1));
System.out.printf("Retrieved issuer with name %s and prodier %s", issuerResponse.getValue().name(),
    issuerResponse.getValue().provider());
```

### python
 ```python
# async
issuer1 = await client.get_issuer(name="issuer1")

print(issuer1.name)
print(issuer1.provider)
print(issuer1.account_id)

# sync
issuer1 = client.get_issuer(name="issuer1")

print(issuer1.name)
print(issuer1.properties.provider)
print(issuer1.account_id)
```
### JS/TS
```ts
const certificateIssuer = await client.getCertificateIssuer("IssuerName");
console.log(certificateIssuer);
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
public virtual Response<Issuer> GetIssuer(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> GetIssuerAsync(string name, CancellationToken cancellationToken = default)
```
### Python
```python
async def get_issuer(self, issuer_name: str, **kwargs: "Any") -> CertificateIssuer:
```
### JS/TS
```ts
  public async getIssuer(
    issuerName: string,
    options?: RequestOptionsBase
  ): Promise<CertificateIssuer>
```

## Scenario - Delete Certificate Issuer
### Usage
### java
```java
//Async
certificateAsyncClient.deleteCertificateIssuerWithResponse("issuerName")
    .subscribe(deletedIssuerResponse ->
        System.out.printf("Deleted issuer with name %s %n", deletedIssuerResponse.getValue().name()));

//Sync
Issuer deletedIssuer = certificateClient.deleteIssuer("certificateName");
System.out.printf("Deleted certificate issuer with name %s and provider id %s", deletedIssuer.name(),
    deletedIssuer.provider());
```

### python
 ```python
# async
await client.delete_issuer(name="issuer1")

# sync
client.delete_issuer(name="issuer1")
```
### JS/TS
```ts
await client.deleteIssuer("IssuerName");
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
public virtual Response<Issuer> DeleteIssuer(string name, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> DeleteIssuerAsync(string name, CancellationToken cancellationToken = default)
```
### Python
```python
async def delete_issuer(self, issuer_name: str, **kwargs: "Any") -> CertificateIssuer:

```
### JS/TS
```ts
  public async deleteIssuer(
    issuerName: string,
    options?: RequestOptionsBase
  ): Promise<CertificateIssuer>
```


## Scenario - List Certificate Issuers
### Usage
### java
```java
//Async
certificateAsyncClient.listIssuers()
    .subscribe(issuerProps -> certificateAsyncClient.getCertificateIssuer(issuerProps)
        .subscribe(issuerResponse -> System.out.printf("Received issuer with name %s and provider %s",
            issuerResponse.name(), issuerResponse.provider())));

//Sync
for (IssuerProperties issuerProps : certificateClient.listIssuers()) {
    Issuer retrievedIssuer = certificateClient.getCertificateIssuer(issuerProps);
    System.out.printf("Received issuer with name %s and provider %s", retrievedIssuer.name(),
        retrievedIssuer.provider());
}
```

### python
 ```python
# async
issuers = client.list_issuers()

async for issuer in issuers:
    print(issuer.name)
    print(issuer.properties.provider)

# sync
issuers = client.list_issuers()

for issuer in issuers:
    print(issuer.name)
    print(issuer.properties.provider)
```

### JS/TS
```ts
// All in one call
for await (const issuer of client.listCertificateIssuers()) {
    console.log(issuer);
}
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
public virtual IEnumerable<Response<IssuerProperties>> GetIssuers(CancellationToken cancellationToken = default)
public virtual IAsyncEnumerable<Response<IssuerProperties>> GetIssuersAsync(CancellationToken cancellationToken = default)
```
### Python
```python
def list_properties_of_issuers(self, **kwargs: "Any") -> AsyncIterable[IssuerProperties]:
```
### JS/TS
```ts
  public listIssuers(
    options?: KeyVaultClientGetCertificateIssuersOptionalParams
  ): PagedAsyncIterableIterator<CertificateIssuer, CertificateIssuer[]>
```

## Scenario - Update Certificate Issuer
### Usage
### java
```java
//Async
certificateAsyncClient.getIssuer("issuerName")
    .subscribe(issuer -> {
        issuer.setAdministrators(Arrays.asList(new Administrator("test", "name", "test@example.com")));
        certificateAsyncClient.updateCertificateIssuer(issuer)
            .subscribe(issuerResponse ->
                System.out.printf("Updated issuer with name %s, provider %s",
                    issuerResponse.name(), issuerResponse.provider()));
    });

//Sync
Issuer returnedIssuer = certificateClient.getIssuer("issuerName");
returnedIssuer.setAdministrators(Arrays.asList(new Administrator("test", "name", "test@example.com")));
Issuer updatedIssuer = certificateClient.updateIssuer(returnedIssuer);
System.out.printf("Updated issuer with name %s, provider %s and account Id %s", updatedIssuer.name(),
    updatedIssuer.provider(), updatedIssuer.accountId());
```

### JS/TS
```ts
await client.updateCertificateIssuer("IssuerName", {
    provider: "Provider2"
});
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
public virtual Response<Issuer> UpdateIssuer(Issuer issuer, CancellationToken cancellationToken = default)
public virtual async Task<Response<Issuer>> UpdateIssuerAsync(Issuer issuer, CancellationToken cancellationToken = default)
```
### Python
```python
async def update_issuer(self, issuer_name: str, **kwargs: "Any") -> CertificateIssuer:
```
### JS/TS
```ts
  public async updateIssuer(
    issuerName: string,
    options?: KeyVaultClientUpdateCertificateIssuerOptionalParams
  ): Promise<CertificateIssuer>
```



## Scenario - Get Certificate Operation
Question: Do we need this, if we have LRO/Poller support ?

### Usage
### JS/TS
```ts
const client = new CertificatesClient(url, credentials);
await client.createCertificate("MyCertificate", {
  issuerParameters: { name: "Self" },
  x509CertificateProperties: { subject: "cn=MyCert" }
});
const operation = await client.getCertificateOperation("MyCertificate");
console.log(operation);
```

### Java
```java
public PollerFlux<CertificateOperation, KeyVaultCertificateWithPolicy> getCertificateOperation(String certificateName)

public SyncPoller<CertificateOperation, KeyVaultCertificateWithPolicy> getCertificateOperation(String certificateName)
```

### .NET
```c#
public virtual CertificateOperation GetCertificateOperation(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<CertificateOperation> GetCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)
```
### Python
```python
async def get_certificate_operation(self, certificate_name: str, **kwargs: "Any") -> CertificateOperation:
```
### JS/TS
```ts
  public async getCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```

## Scenario - Cancel Certificate Operation
### Usage
### java
```java
//Async
certificateAsyncClient.cancelCertificateOperation("certificateName")
    .subscribe(certificateOperation -> System.out.printf("Certificate operation status %s",
        certificateOperation.status()));

//Sync
CertificateOperation certificateOperation = certificateClient.cancelCertificateOperation("certificateName");
System.out.printf("Certificate Operation status %s", certificateOperation.status());
```

### JS/TS
```ts
await client.cancelCertificateOperation("MyCertificate");
```
### API
### Java
```java
public Mono<CertificateOperation> cancelCertificateOperation(String certificateName);
public Mono<Response<CertificateOperation>> cancelCertificateOperation(String certificateName);

public CertificateOperation cancelCertificateOperation(String certificateName);
public Response<CertificateOperation> cancelCertificateOperation(String certificateName);
```

### .NET
```c#
public virtual CertificateOperation CancelCertificateOperation(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<CertificateOperation> CancelCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)

```
### Python
```python
async def cancel_certificate_operation(self, certificate_name: str, **kwargs: "Any") -> CertificateOperation:
```
### JS/TS
```ts
  public async cancelCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```

## Scenario - Delete Certificate Operation
### Usage
### java
```java
//Async
certificateAsyncClient.deleteCertificateOperationWithResponse("certificateName")
    .subscribe(certificateOperationResponse -> System.out.printf("Deleted Certificate operation's last"
        + " status %s", certificateOperationResponse.getValue().status()));

//Sync
CertificateOperation deletedCertificateOperation = certificateClient.deleteCertificateOperation("certificateName");
System.out.printf("Deleted Certificate Operation's last status %s", deletedCertificateOperation.status());
```

### JS/TS
```ts
await client.deleteCertificateOperation("MyCertificate");
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
public virtual CertificateOperation DeleteCertificateOperation(string certificateName, CancellationToken cancellationToken = default)
public virtual async Task<CertificateOperation> DeleteCertificateOperationAsync(string certificateName, CancellationToken cancellationToken = default)
```
### Python
```python
async def delete_certificate_operation(self, certificate_name: str, **kwargs: "Any") -> CertificateOperation:
```
### JS/TS
```ts
 public async deleteCertificateOperation(
    name: string,
    options?: RequestOptionsBase
  ): Promise<CertificateOperation>
```



## Scenario - Set Certificate Contacts
### Usage
### java
```java
//Async
Contact contactToAdd = new Contact("user", "useremail@exmaple.com");
certificateAsyncClient.setContacts(Arrays.asList(contactToAdd)).subscribe(contact ->
    System.out.printf("Contact name %s and email %s", contact.name(), contact.emailAddress())
);

//Sync
Contact contactToAdd = new Contact("user", "useremail@exmaple.com");
for (Contact contact : certificateClient.setContacts(Arrays.asList(contactToAdd))) {
    System.out.printf("Added contact with name %s and email %s to key vault", contact.name(),
        contact.emailAddress());
}
```

### JS/TS
 ```ts
let client = new CertificatesClient(url, credentials);
await client.setContacts([{
   emailAddress: "b@b.com",
   name: "b",
   phone: "222222222222"
 }]);
await client.deleteCertificateContacts();
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
public virtual Response<IList<Contact>> SetContacts(IEnumerable<Contact> contacts, CancellationToken cancellationToken = default)
public virtual async Task<Response<IList<Contact>>> SetContactsAsync(IEnumerable<Contact> contacts, CancellationToken cancellationToken = default)
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
    contacts: Contact[],
    options?: RequestOptionsBase
  ): Promise<Contacts>
```

## Scenario - List Certificate Contacts
### Usage
### java
```java
//Async
certificateAsyncClient.listContacts().subscribe(contact ->
    System.out.printf("Contact name %s and email %s", contact.name(), contact.emailAddress())
);

//Sync
for (Contact contact : certificateClient.listContacts()) {
    System.out.printf("Added contact with name %s and email %s to key vault", contact.name(),
        contact.emailAddress());
}
```

### JS/TS
 ```ts
const getResponse = await client.getContacts();
console.log(getResponse.contactList!);
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
public virtual Response<IList<Contact>> GetContacts(CancellationToken cancellationToken = default)
public virtual async Task<Response<IList<Contact>>> GetContactsAsync(CancellationToken cancellationToken = default)
```
### Python
```python
async def get_contacts(self, **kwargs: "Any") -> List[CertificateContact]:
```
### JS/TS
```ts
public async getContacts(options?: RequestOptionsBase): Promise<Contacts>
```

## Scenario - Delete Certificate Contacts
### Usage
### java
```java
//Async
certificateAsyncClient.deleteContacts().subscribe(contact ->
    System.out.printf("Deleted Contact name %s and email %s", contact.name(), contact.emailAddress())
);

//Sync
for (Contact contact : certificateClient.deleteContacts()) {
    System.out.printf("Deleted contact with name %s and email %s from key vault", contact.name(),
        contact.emailAddress());
}
```

### JS/TS
 ```ts
await client.deleteContacts();
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
public virtual Response<IList<Contact>> DeleteContacts(CancellationToken cancellationToken = default)
public virtual async Task<Response<IList<Contact>>> DeleteContactsAsync(CancellationToken cancellationToken = default)
```
### Python
```python
async def delete_contacts(self, **kwargs: "Any") -> List[CertificateContact]:
```
### JS/TS
```ts
  public async deleteContacts(options?: RequestOptionsBase): Promise<Contacts>
```

## Scenario - Get Certificate Signing Request
### Usage
### java
```java
//Async
certificateAsyncClient.getPendingCertificateSigningRequest("certificateName")
    .subscribe(signingRequest -> System.out.printf("Received Signing request blob of length %s",
        signingRequest.length));

//Sync
byte[] signingRequest = certificateClient.getPendingCertificateSigningRequest("certificateName");
System.out.printf("Received Signing request blob of length %s", signingRequest.length);
```
### API
### Java
```java
public Mono<byte[]> getPendingCertificateSigningRequest(String certificateName);
public Mono<Response<byte[]>> getPendingCertificateSigningRequestWithResponse(String certificateName);

public byte[] getPendingCertificateSigningRequest(String certificateName);
public Response<byte[]> getPendingCertificateSigningRequestWithResponse(String certificateName, Context context);
```

### .NET
```c#
Not in Master.
```
### Python
```python
    def get_pending_certificate_signing_request(
        self,
        name,  # type: str
        **kwargs  # type: **Any
    ):
```
### JS/TS
```ts
Not in Master
```


## Scenario - Merge Certificate
### Usage
### java
 ```ts
const client = new CertificatesClient(url, credentials);
await client.createCertificate("MyCertificate", {
  issuerParameters: {
    name: "Unknown",
    certificateTransparency: false
   },
   x509CertificateProperties: { subject: "cn=MyCert" }
 });
const { csr } = await client.getCertificateOperation(certificateName);
const base64Csr = Buffer.from(csr!).toString("base64");
const wrappedCsr = ["-----BEGIN CERTIFICATE REQUEST-----", base64Csr, "-----END CERTIFICATE REQUEST-----"].join("\n");
fs.writeFileSync("test.csr", wrappedCsr);

// Certificate available locally made using:
// openssl genrsa -out ca.key 2048
// openssl req -new -x509 -key ca.key -out ca.crt
// You can read more about how to create a fake certificate authority here: https://gist.github.com/Soarez/9688998
childProcess.execSync("openssl x509 -req -in test.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out test.crt");
const base64Crt = fs.readFileSync("test.crt").toString().split("\n").slice(1, -1).join("");

await client.mergeCertificate(certificateName, [Buffer.from(base64Crt)]);
 ```

### JS/TS
 ```ts
await client.deleteContacts();
```

### Java
```java
public Mono<KeyVaultCertificate> mergeCertificate(MergeCertificateOptions mergeCertificateOptions)
public Mono<Response<KeyVaultCertificateWithPolicy>> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateOptions)

public KeyVaultCertificateWithPolicy mergeCertificate(MergeCertificateOptions mergeCertificateOptions)
public Response<KeyVaultCertificateWithPolicy> mergeCertificateWithResponse(MergeCertificateOptions mergeCertificateOptions, Context context)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> MergeCertificate(CertificateMergeOptions certificateMergeOptions, CancellationToken cancellationToken = default);

public virtual async Task<Response<CertificateWithPolicy>> MergeCertificateAsync(CertificateMergeOptions certificateMergeOptions, CancellationToken cancellationToken = default);
```
### Python
```python
async def merge_certificate(
        self, certificate_name: str, x509_certificates: List[bytearray], **kwargs: "Any"
    ) -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async mergeCertificate(
    name: string,
    x509Certificates: Uint8Array[],
    options?: RequestOptionsBase
  ): Promise<Certificate>
```

## Scenario - Import Certificate
### Usage
```ts
const client = new CertificatesClient(url, credentials);
const certificateSecret = await secretsClient.getSecret("MyCertificate");
const base64EncodedCertificate = certificateSecret.value!;
await client.importCertificate("MyCertificate", base64EncodedCertificate);
```

### Java
```java
public Mono<KeyVaultCertificateWithPolicy> importCertificate(ImportCertificateOptions importCertificateOptions)
public Mono<Response<KeyVaultCertificateWithPolicy>> importCertificateWithResponse(ImportCertificateOptions importCertificateOptions)

public KeyVaultCertificateWithPolicy importCertificate(ImportCertificateOptions importCertificateOptions)
public Response<KeyVaultCertificateWithPolicy> importCertificateWithResponse(ImportCertificateOptions importCertificateOptions, Context context)
```

### .NET
```c#
public virtual Response<CertificateWithPolicy> ImportCertificate(CertificateImport import, CancellationToken cancellationToken = default)
public virtual async Task<Response<CertificateWithPolicy>> ImportCertificateAsync(CertificateImport import, CancellationToken cancellationToken = default)
```

### Python
```python
async def import_certificate(
        self, certificate_name: str, certificate_bytes: bytes, **kwargs: "Any"
    ) -> KeyVaultCertificate:
```
### JS/TS
```ts
  public async importCertificate(
    name: string,
    base64EncodedCertificate: string,
    options?: KeyVaultClientImportCertificateOptionalParams
  ): Promise<Certificate>
```

## Certifciates Datastructures Design
## KeyVaultCertificate
### .NET
```c#
public class KeyVaultCertificate : IJsonDeserializable {
    public byte[] Cer { get; }
    public CertificateContentType ContentType { get; }
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
/**
 * An interface representing a certificate without the certificate's policy
 */
export interface KeyVaultCertificate {
  /**
   * CER contents of x509 certificate.
   */
  cer?: Uint8Array;
  /**
   * The content type of the secret.
   */
  certificateContentType?: CertificateContentType;
  /**
   * Certificate identifier.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  id?: string;
  /**
   * The key id.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly keyId?: string;
  /**
   * The secret id.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly secretId?: string;
  /**
   * The name of certificate.
   */
  name: string;
  /**
   * The properties of the certificate
   */
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
public class KeyVaultCertificateWithPolicy extends KeyVaultCertificate {
    public CertificateProperties getProperties() {} // I'm not seeing this defined in the keyvaultcertificatepolicy class
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
/**
 * An interface representing a certificate with its policy
 */
export interface KeyVaultCertificateWithPolicy extends KeyVaultCertificate {
  /**
   * The management policy.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
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
/**
 * An interface representing the properties of a certificate
 */
export interface CertificateProperties {
  /**
   * When the certificate was created.
   */
  readonly createdOn?: Date;
  /**
   * Determines whether the object is enabled.
   */
  enabled?: boolean;
  /**
   * Expiry date in UTC.
   */
  readonly expiresOn?: Date;
  /**
   * Certificate identifier.
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  id?: string;
  /**
   * The name of certificate.
   */
  name?: string;
  /**
   * Not before date in UTC.
   */
  notBefore?: Date;
  /**
   * Reflects the deletion recovery level currently in effect for certificates in the current
   * vault. If it contains 'Purgeable', the certificate can be permanently deleted by a privileged
   * user; otherwise, only the system can purge the certificate, at the end of the retention
   * interval. Possible values include: 'Purgeable', 'Recoverable+Purgeable', 'Recoverable',
   * 'Recoverable+ProtectedSubscription'
   * **NOTE: This property will not be serialized. It can only be populated by the server.**
   */
  readonly recoveryLevel?: DeletionRecoveryLevel;
  /**
   * Application specific
   * metadata in the form of key-value pairs.
   */
  tags?: CertificateTags;
  /**
   * When the issuer was updated.
   */
  updatedOn?: Date;
  /**
   * The vault URI.
   */
  vaultUrl?: string;
  /**
   * The version of certificate. May be undefined.
   */
  version?: string;
  /**
   * Thumbprint of the certificate.
   */
  readonly x509Thumbprint?: Uint8Array;
}

```

## CertificateOperation
### .NET
```c#
public class CertificateOperation : Operation<KeyVaultCertificateWithPolicy> {
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
    public string CertificateSigningRequest { get; }
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
        error=None,  # type: Optional[models.Error]
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
/**
 * A certificate operation is returned in case of asynchronous requests.
 */
export interface CertificateOperation {
  /**
   * The certificate id.
   * **NOTE: This property will not be serialized. It can only be populated by the server.**
   */
  readonly id?: string;
  /**
   * Parameters for the issuer of the X509 component of a certificate.
   */
  issuerParameters?: IssuerParameters;
  /**
   * The certificate signing request (CSR) that is being used in the certificate operation.
   */
  csr?: Uint8Array;
  /**
   * Indicates if cancellation was requested on the certificate operation.
   */
  cancellationRequested?: boolean;
  /**
   * Status of the certificate operation.
   */
  status?: string;
  /**
   * The status details of the certificate operation.
   */
  statusDetails?: string;
  /**
   * Error encountered, if any, during the certificate operation.
   */
  error?: ErrorModel;
  /**
   * Location which contains the result of the certificate operation.
   */
  target?: string;
  /**
   * Identifier for the certificate operation.
   */
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
n/a
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
/**
 * An interface representing a deleted certificate
 */
export interface DeletedCertificate extends KeyVaultCertificateWithPolicy {
  /**
   * The time when the certificate was deleted, in UTC
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
  readonly deletedOn?: Date;
  /**
   * The url of the recovery object, used to
   * identify and recover the deleted certificate.
   */
  recoveryId?: string;
  /**
   * The time when the certificate is scheduled
   * to be purged, in UTC
   * **NOTE: This property will not be serialized. It can only be populated by
   * the server.**
   */
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
    public bool? CertificateTransparency { get; set; }
    public string CertificateType { get; set; }
    public CertificateContentType? ContentType { get; set; }
    public DateTimeOffset? CreatedOn { get; }
    public static CertificatePolicy Default { get; }
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
    public List<CertificateKeyUsage> getKeyUsage()
    public CertificatePolicy setKeyUsage(CertificateKeyUsage... keyUsage)
    public List<String> getEnhancedKeyUsage()
    public CertificatePolicy setEnhancedKeyUsage(List<String> ekus)
    public Boolean isExportable()
    public CertificatePolicy setExportable(Boolean exportable)
    public CertificateKeyType getKeyType()
    public CertificatePolicy setKeyType(CertificateKeyType keyType)
    public Integer getKeySize()
    public CertificatePolicy setKeySize(Integer keySize)
    public Boolean isKeyReusable()
    public CertificatePolicy setKeyReusable(Boolean keyReusable)
    public CertificateKeyCurveName getKeyCurveName()
    public CertificatePolicy setKeyCurveName(CertificateKeyCurveName keyCurveName) {}
    public CertificatePolicy setKeyCurveName(CertificateKeyCurveName keyCurveName)
    public OffsetDateTime getCreatedOn()
    public OffsetDateTime getUpdatedOn()
    public Boolean isEnabled()
    public CertificatePolicy setEnabled(Boolean enabled)
    public CertificateContentType getContentType()
    public CertificatePolicy setContentType(CertificateContentType contentType)
    public CertificatePolicy getSubjectName(String subjectName)
    public SubjectAlternativeNames getSubjectAlternativeNames()
    public CertificatePolicy setSubjectAlternativeNames(SubjectAlternativeNames subjectAlternativeNames)
    public Integer getValidityInMonths()
    public CertificatePolicy setValidityInMonths(Integer validityInMonths)
    public String getIssuerName()
    public CertificatePolicy setIssuerName(String issuerName)
    public String getCertificateType()
    public CertificatePolicy setCertificateType(String certificateType)
    public Boolean isCertificateTransparent()
    public CertificatePolicy setCertificateTransparent(Boolean certificateTransparent)
    public String getSubject() // not seeing a setSubject
    public List<LifetimeAction> getLifetimeActions()
    public CertificatePolicy setLifetimeActions(LifetimeAction... actions)
    public static CertificatePolicy getDefault()
}
```

### Python
```python
def __init__(
        self,
        issuer_name,  # type: str
        **kwargs  # type: Any
    ):
@property
    def id(self):
        # type: () -> str
    @property
    def exportable(self):
        # type: () -> bool
    @property
    def key_type(self):
        # type: () -> KeyType
    @property
    def key_size(self):
        # type: () -> int
    @property
    def reuse_key(self):
        # type: () -> bool
    @property
    def key_curve_name(self):
        # type: () -> KeyCurveName
    @property
    def enhanced_key_usage(self):
        # type: () -> List[str]
    @property
    def key_usage(self):
        # type: () -> List[KeyUsageType]
    @property
    def content_type(self):
        # type: () -> CertificateContentType
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
    def validity_in_months(self):
        # type: () -> int
    @property
    def lifetime_actions(self):
        # type: () -> List[LifetimeAction]
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
```
### JS/TS
```ts
/**
 * An interface representing a certificate's policy
 */
export interface CertificatePolicy {
  /**
   * Indicates if the certificates generated under this policy should be published to certificate
   * transparency logs.
   */
  certificateTransparency?: boolean;
  /**
   * The media type (MIME type).
   */
  contentType?: string;
  /**
   * Type of certificate to be requested from the issuer provider.
   */
  certificateType?: CertificateContentType;
  /**
   * When the certificate was created.
   */
  readonly createdOn?: Date;
  /**
   * Determines whether the object is enabled.
   */
  enabled?: boolean;
  /**
   * The enhanced key usage.
   */
  enhancedKeyUsage?: string[];
  /**
   * Name of the referenced issuer object or reserved names; for example, 'Self' or 'Unknown'.
   */
  issuerName?: WellKnownIssuer | string;
  /**
   * Elliptic curve name. Possible values include: 'P-256', 'P-384', 'P-521', 'P-256K'
   */
  keyCurveName?: KeyCurveName;
  /**
   * The key size in bits. For example: 2048, 3072, or 4096 for RSA.
   */
  keySize?: number;
  /**
   * The type of key pair to be used for the certificate. Possible values include: 'EC', 'EC-HSM',
   * 'RSA', 'RSA-HSM', 'oct'
   */
  keyType?: KeyType;
  /**
   * List of key usages.
   */
  keyUsage?: KeyUsageType[];
  /**
   * Actions that will be performed by Key Vault over the lifetime of a certificate.
   */
  lifetimeActions?: LifetimeAction[];
  /**
   * Indicates if the same key pair will be used on certificate renewal.
   */
  reuseKey?: boolean;
  /**
   * The subject name. Should be a valid X509 distinguished Name.
   */
  subject?: string;
  /**
   * The subject alternative names.
   */
  subjectAlternativeNames?: SubjectAlternativeNames;
  /**
   * When the object was updated.
   */
  readonly updatedOn?: Date;
  /**
   * The duration that the certificate is valid in months.
   */
  validityInMonths?: number;
}

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
### JS/TS
```ts
export type CertificateContentType = "application/pem" | "application/x-pkcs12" | undefined;
```


## CertificateKeyUsage
### .NET
```c#
public struct CertificateKeyUsage : IEquatable<CertificateKeyUsage> {
    public CertificateKeyUsage(string value);
    public static CertificateKeyUsage CrlSign { get; }
    public static CertificateKeyUsage DataEncipherment { get; }
    public static CertificateKeyUsage DecipherOnly { get; }
    public static CertificateKeyUsage DigitalSignature { get; }
    public static CertificateKeyUsage EncipherOnly { get; }
    public static CertificateKeyUsage KeyAgreement { get; }
    public static CertificateKeyUsage KeyCertSign { get; }
    public static CertificateKeyUsage KeyEncipherment { get; }
    public static CertificateKeyUsage NonRepudiation { get; }
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
/**
 * Defines values for KeyUsageType.
 * Possible values include: 'digitalSignature', 'nonRepudiation', 'keyEncipherment',
 * 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'
 * @readonly
 * @enum {string}
 */
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
n/a
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
/**
 * Action and its trigger that will be performed by Key Vault over the lifetime of a certificate.
 */
export interface LifetimeAction {
  /**
   * The condition that will execute the action.
   */
  trigger?: Trigger;
  /**
   * The action that will be executed.
   */
  action?: Action;
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
/**
 * An interface representing the alternative names of the subject of a certificate policy.
 */
export interface SubjectAlternativeNamesAll {
  /**
   * Email addresses.
   */
  emails: ArrayOneOrMore<string>;
  /**
   * Domain names.
   */
  dnsNames: ArrayOneOrMore<string>;
  /**
   * User principal names.
   */
  userPrincipalNames: ArrayOneOrMore<string>;
}

/**
 * Alternatives to the subject property.
 * If present, it should at least have one of the properties of SubjectAlternativeNamesAll.
 */
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
/**
 * Defines values for JsonWebKeyCurveName.
 * Possible values include: 'P-256', 'P-384', 'P-521', 'P-256K'
 * @readonly
 * @enum {string}
 */
export type JsonWebKeyCurveName = "P-256" | "P-384" | "P-521" | "P-256K";
```


## CertificateKeyType
### .NET
```c#
public struct CertificateKeyType : IEquatable<CertificateKeyType> {
    public CertificateKeyType(string value);
    public static CertificateKeyType Ec { get; }
    public static CertificateKeyType EcHsm { get; }
    public static CertificateKeyType Oct { get; }
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
/**
 * Defines values for JsonWebKeyType.
 * Possible values include: 'EC', 'EC-HSM', 'RSA', 'RSA-HSM', 'oct'
 * @readonly
 * @enum {string}
 */
export type JsonWebKeyType = "EC" | "EC-HSM" | "RSA" | "RSA-HSM" | "oct";
```


## MergeCertificateOptions
### .NET
```c#
public class MergeCertificateOptions : IJsonSerializable {
    public MergeCertificateOptions(string name, IEnumerable<byte[]> x509certificates);
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
/**
 * An interface representing optional parameters for {@link mergeCertificate}.
 */
export interface MergeCertificateOptions extends coreHttp.OperationOptions {}
```


## ImportCertificateOptions
### .NET
```c#
public class ImportCertificateOptions : IJsonSerializable {
    public ImportCertificateOptions(string name, byte[] value, CertificatePolicy policy);
    public bool? Enabled { get; set; }
    public string Name { get; }
    public string Password { get; set; }
    public CertificatePolicy Policy { get; }
    public IDictionary<string, string> Tags { get; }
    public byte[] Value { get; }
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
/**
 * Options for {@link importCertificate}.
 */
export interface ImportCertificateOptions extends CertificateProperties, coreHttp.OperationOptions {
  /**
   * If the private key in base64EncodedCertificate is encrypted, the password used for encryption.
   */
  password?: string;
}
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
/**
 * Well known issuers for choosing a default
 */
export enum WellKnownIssuer {
  /**
   * For self signed certificates
   */
  Self = "Self",
  /**
   * For certificates whose issuer will be defined later
   */
  Unknown = "Unknown",
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
/**
 * Details of the organization administrator of the certificate issuer.
 */
export interface AdministratorContact {
  /**
   * First name.
   */
  firstName?: string;
  /**
   * Last name.
   */
  lastName?: string;
  /**
   * Email address.
   */
  emailAddress?: string;
  /**
   * Phone number.
   */
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
/**
 * The contact information for the vault certificates.
 * Each contact will have at least just one of the properties of CertificateContactAll,
 * which are: emailAddress, name or phone.
 */
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
    public OffsetDateTime getCreated()
    public OffsetDateTime getUpdated()
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
/**
 * An interface representing the properties of an issuer
 */
export interface CertificateIssuer {
  /**
   * Certificate Identifier.
   */
  id?: string;
  /**
   * The issuer provider.
   */
  provider?: string;
  /**
   * Determines whether the object is enabled.
   */
  enabled?: boolean;
  /**
   * When the issuer was created.
   */
  createdOn?: Date;
  /**
   * When the issuer was updated.
   */
  updatedOn?: Date;
  /**
   * Name of the issuer
   */
  name?: string;
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
/**
 * An interface representing the issuer of a certificate
 */
export interface IssuerProperties {
  /**
   * Certificate Identifier.
   */
  id?: string;
  /**
   * The issuer provider.
   */
  provider?: string;
}

```

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign4.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign5.png)

![](https://github.com/g2vinay/KVSpec/blob/master/CertsDesign6.png)
