# Fwoosh Privacy Policy

**Last updated:** July 12, 2026  
**Effective date:** July 12, 2026

> Before publishing this policy, replace the bracketed placeholders with the
> correct legal entity, address, and privacy contact. This document is a
> product-specific starting point, not legal advice.

This Privacy Policy explains how **[LEGAL ENTITY / FWOOSH MAINTAINERS]** ("Fwoosh," "we," "us," or "our") handles information in connection with the Fwoosh desktop and mobile applications, related relay services, and official distribution channels, as made available from time to time (collectively, the "App" and "Services").

Fwoosh is designed as a peer-to-peer clipboard and file-sharing application. The App can use a public ntfy.sh relay, a relay selected by the customer, or—if offered as part of a paid plan—a relay operated by Fwoosh and its infrastructure partners. We do not operate a central plaintext content database or central plaintext file-storage service.

## 1. Information we do not intentionally collect

When you use the App, we do not intentionally collect or receive through our own servers:

- account registration information, such as your name, email address, or password;
- advertising identifiers or behavioral analytics;
- the plaintext contents of clips or transferred files; or
- a centralized copy of your clipboard history or files.

The App may still communicate with third-party infrastructure that can observe network metadata. See Section 4.

## 2. Information processed by the App

### Information stored on your devices

The App processes and stores information locally so it can provide its features. Depending on how you use the App, this may include:

- clipboard text that you choose to send and received clips saved in local history;
- files you choose to send, received files, file names, file sizes, and transfer status;
- device labels that you create or accept for paired devices;
- room membership, pairing information, cryptographic keys, signed device records, and revocation records;
- local timestamps, message identifiers, replay-protection data, and encrypted transfer history;
- your selected theme and App settings; and
- notification permission state and operating-system notification data, if notifications are enabled.

Clip history and security material are intended to be protected using local encryption and the operating system credential store where available. Anyone who can access your logged-in operating-system account, unlocked device, local files, or paired devices may nevertheless be able to access information available to the App.

You can delete clip history and file-transfer history from the App. Uninstalling the App may not remove every operating-system or user-created backup; check your operating system and backup tools separately.

### Information sent through the transport layer

To synchronize devices, Fwoosh sends encrypted messages and encrypted file-transfer signaling through an ntfy-compatible relay. Depending on the release and configuration, that relay may be operated by ntfy.sh, by the customer or another administrator, or by Fwoosh and its infrastructure partners.

The relay may be able to observe or log information such as:

- IP address and connection information;
- topic or room identifiers, which may be treated as sensitive because they help route messages;
- connection times, message timing, message sizes, and delivery status; and
- encrypted payloads and encrypted signaling data.

Fwoosh is designed so that clip contents and file-transfer contents are encrypted before they leave your device. The relay operator can deliver and temporarily store encrypted payloads, but is not given the keys needed to decrypt supported content. End-to-end encryption does not hide all metadata and does not protect a device that is compromised or unlocked.

The public ntfy.sh service currently documents temporary message caching and server logs in its own privacy materials. Its operator controls that service's retention and processing. Review the [ntfy privacy policy](https://docs.ntfy.sh/privacy/) and [ntfy publishing documentation](https://docs.ntfy.sh/publish/) before using the public relay for sensitive material. If you use a customer-selected or self-hosted relay, that relay operator controls its retention and processing. If you use a Fwoosh-operated relay, Section 4 explains the metadata that Fwoosh and its infrastructure partners may process.

### Peer-to-peer networking

File transfers use WebRTC data channels and may use configured STUN servers to establish a connection. STUN and network providers may process IP addresses, network information, and connection timing. You can review or change the configured STUN servers in the App, subject to the App's available settings and the provider's own terms and privacy policy.

## 3. How we use information

We use information processed by the App only as needed to:

- provide clipboard synchronization, pairing, device management, and file transfers;
- secure communications, authenticate paired devices, detect replayed or invalid messages, and support revocation;
- save, search, display, and delete local history at your direction;
- maintain, troubleshoot, secure, and improve the App when information is available to us; and
- comply with law, respond to valid legal process, and protect the rights, safety, and security of users and the project.

For local or customer-selected relay use, most processing occurs locally or through the transport and networking providers you choose. If you use a Fwoosh-operated relay or a Pro service, Fwoosh and its service providers may also process the operational metadata described below.

## 4. Third-party services and disclosures

Fwoosh may connect to services that you select or that are configured by default, including:

- **Public ntfy.sh relay:** the default relay for some releases or configurations. ntfy.sh is operated independently of Fwoosh and has its own [privacy policy](https://docs.ntfy.sh/privacy/) and [terms of service](https://docs.ntfy.sh/terms/).
- **Customer-selected or self-hosted ntfy relay:** a relay selected, operated, or administered by you, your employer, a partner, or another organization. That operator may process the relay metadata listed in Section 2 and controls its own retention, logging, and access practices.
- **Fwoosh-operated relay:** if Fwoosh offers a Pro or other managed relay plan, Fwoosh and the hosting, networking, security, and support partners needed to operate that relay may process operational metadata, including IP address, topic or room identifier, connection and delivery timestamps, message size, connection status, rate-limit and abuse-prevention events, and limited technical logs. These parties may temporarily handle encrypted payloads for routing and offline delivery, but Fwoosh is not designed to have the decryption keys for supported clip and file content.
- **STUN or other WebRTC infrastructure:** used to help establish peer-to-peer connections. The applicable provider's privacy policy governs its processing.
- **Your operating system:** used for secure credential storage, local files, clipboard access, window/tray integration, and optional notifications. Your operating system's privacy and security controls apply.

If we later offer accounts or a Pro plan, we may also process information needed to provide those features, such as an email or account identifier, subscription status, payment-provider customer identifier, support communications, mobile push-token or app-install information, and service health or security logs. We will update this policy before collecting information for a materially new feature.

We do not sell personal information. We do not intentionally disclose plaintext clip or file contents to Fwoosh-operated servers or infrastructure partners. We may disclose information available to us if required by law, to protect the App or its users, or in connection with a transfer of the project or its assets.

## 5. Retention

Local information remains on your device until you delete it, the App deletes it as part of normal operation, or it is overwritten or removed by your operating system or backup process. Public, customer-selected, and self-hosted relay retention is controlled by the relevant relay operator and its configuration. For a Fwoosh-operated relay, encrypted message caching and operational logs are retained only for as long as reasonably necessary for delivery, security, abuse prevention, troubleshooting, legal compliance, and service administration, subject to the specific plan documentation we publish. We do not control or guarantee third-party retention periods.

## 6. Security

Fwoosh is designed with defense in depth across content encryption, sender authentication, membership control, and local data protection.

**Content encryption.** Each clip is encrypted with a fresh random content key using XChaCha20-Poly1305 authenticated encryption. The content key is then wrapped separately for each intended recipient using HPKE (Hybrid Public Key Encryption, RFC 9180), so only the devices you have paired can decrypt it. The relay handles and temporarily stores only encrypted payloads and never receives the decryption keys for supported content.

**Sender authenticity and integrity.** Every clip manifest is signed with the sender's Ed25519 key over canonical bytes with a protocol-specific domain separator, providing sender authentication and tamper detection. Encrypted chunk ciphertexts are covered by a SHA-256 Merkle root included in the signed manifest, so swapped, truncated, or substituted chunks are detected on receipt.

**Membership control and revocation.** Device membership is tracked in an append-only, hash-chained roster log signed by the admin device's Ed25519 key. Each roster epoch records the full active and revoked device lists. Clips are pinned to a specific roster epoch, and receivers reject messages from stale or unknown epochs. When a device is revoked, the admin rotates the relay topic and distributes the updated roster to remaining devices through an encrypted channel, so a removed device can no longer observe metadata on the active topic.

**Replay protection.** A local cache of seen message identifiers is maintained to detect and reject replayed messages.

**Local data protection.** Clip history text is encrypted at rest with XChaCha20-Poly1305 using a database key that is separate from the device keypairs and stored in the operating system credential store (Windows Credential Manager, macOS Keychain, or Linux Secret Service). Device private keys are likewise stored in the OS credential store, not in plaintext files.

**File transfer security.** File transfers stream over WebRTC data channels. Each chunk is individually encrypted with XChaCha20-Poly1305 using a per-transfer content key, with the session identifier and chunk index bound into the authenticated data. A SHA-256 checksum of the plaintext stream is sent in a final authenticated frame and verified by the receiver before the transfer is considered complete.

**Known limitations.** No software, encryption system, network, or storage method is completely secure. End-to-end encryption does not hide all metadata: the relay can observe topic identifiers, timing, message sizes, and IP addresses. Fwoosh does not currently implement forward secrecy (ratcheting); device keys are stable for the current version. Anyone who can access your logged-in operating-system account, unlocked device, local files, or paired devices may be able to access information available to the App. You are responsible for securing your devices, pairing codes, relay configuration, operating-system account, and backups. Fwoosh does not promise that content will always be delivered, that metadata will be concealed, or that a compromised endpoint can be protected.

## 7. Your choices and privacy rights

You can generally:

- choose whether to pair devices and which clips or files to send;
- use a self-hosted relay where supported;
- configure or remove STUN servers in the App;
- disable optional notifications through the App or your operating system;
- delete local clip and file history; and
- stop using the App and remove its local data.

Depending on where you live, you may have rights to access, correct, delete, restrict, object to, or obtain a copy of personal information, or to complain to a privacy regulator. Some requests may need to be directed to the relay, STUN provider, operating-system provider, or paired-device owner because Fwoosh may not possess the relevant information.

To make a privacy request about information we control, contact **[PRIVACY CONTACT EMAIL]**. We may need enough information to verify and respond to the request. You may also have the right to contact the privacy regulator in your jurisdiction.

## 8. Children

The App is not directed to children and is not intended for use in violation of applicable age requirements. We do not knowingly collect personal information from children through a Fwoosh-operated account system.

## 9. International processing

Third-party relay, networking, distribution, and infrastructure providers may process information in countries other than the country where you live. Their own policies describe their processing and transfer practices.

## 10. Changes to this policy

We may update this policy when the App, its infrastructure, or applicable law changes. We will update the "Last updated" date and, where appropriate, provide additional notice through the project or release channel.

## 11. Contact

**[LEGAL ENTITY / FWOOSH MAINTAINERS]**  
**[MAILING ADDRESS OR BUSINESS ADDRESS]**  
**Privacy contact:** [PRIVACY CONTACT EMAIL]
