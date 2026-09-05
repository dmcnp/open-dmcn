import * as $protobuf from "protobufjs";
import Long = require("long");
/** Namespace dmcn. */
export namespace dmcn {

    /** Namespace identity. */
    namespace identity {

        /** VerificationTier enum. */
        enum VerificationTier {
            VERIFICATION_TIER_UNVERIFIED = 0,
            VERIFICATION_TIER_DOMAIN_DNS = 2,
            VERIFICATION_TIER_DANE = 3
        }

        /** AttestationType enum. */
        enum AttestationType {
            ATTESTATION_TYPE_UNSPECIFIED = 0,
            ATTESTATION_TYPE_IN_PERSON = 1,
            ATTESTATION_TYPE_FINGERPRINT = 2,
            ATTESTATION_TYPE_NETWORK = 3,
            ATTESTATION_TYPE_ORGANISATIONAL = 4
        }

        /** Properties of an AttestationRecord. */
        interface IAttestationRecord {

            /** AttestationRecord attesterAddress */
            attesterAddress?: (string|null);

            /** AttestationRecord attesterPubkey */
            attesterPubkey?: (Uint8Array|null);

            /** AttestationRecord subjectAddress */
            subjectAddress?: (string|null);

            /** AttestationRecord subjectPubkey */
            subjectPubkey?: (Uint8Array|null);

            /** AttestationRecord attestationType */
            attestationType?: (dmcn.identity.AttestationType|null);

            /** AttestationRecord attestedAt */
            attestedAt?: (number|Long|null);

            /** AttestationRecord expiresAt */
            expiresAt?: (number|Long|null);

            /** AttestationRecord signature */
            signature?: (Uint8Array|null);
        }

        /** Represents an AttestationRecord. */
        class AttestationRecord implements IAttestationRecord {

            /**
             * Constructs a new AttestationRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IAttestationRecord);

            /** AttestationRecord attesterAddress. */
            public attesterAddress: string;

            /** AttestationRecord attesterPubkey. */
            public attesterPubkey: Uint8Array;

            /** AttestationRecord subjectAddress. */
            public subjectAddress: string;

            /** AttestationRecord subjectPubkey. */
            public subjectPubkey: Uint8Array;

            /** AttestationRecord attestationType. */
            public attestationType: dmcn.identity.AttestationType;

            /** AttestationRecord attestedAt. */
            public attestedAt: (number|Long);

            /** AttestationRecord expiresAt. */
            public expiresAt: (number|Long);

            /** AttestationRecord signature. */
            public signature: Uint8Array;

            /**
             * Creates a new AttestationRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AttestationRecord instance
             */
            public static create(properties?: dmcn.identity.IAttestationRecord): dmcn.identity.AttestationRecord;

            /**
             * Encodes the specified AttestationRecord message. Does not implicitly {@link dmcn.identity.AttestationRecord.verify|verify} messages.
             * @param message AttestationRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IAttestationRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified AttestationRecord message, length delimited. Does not implicitly {@link dmcn.identity.AttestationRecord.verify|verify} messages.
             * @param message AttestationRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IAttestationRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AttestationRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns AttestationRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.AttestationRecord;

            /**
             * Decodes an AttestationRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns AttestationRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.AttestationRecord;

            /**
             * Verifies an AttestationRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an AttestationRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns AttestationRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.AttestationRecord;

            /**
             * Creates a plain object from an AttestationRecord message. Also converts values to other types if specified.
             * @param message AttestationRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.AttestationRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this AttestationRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for AttestationRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an IdentityRecord. */
        interface IIdentityRecord {

            /** IdentityRecord version */
            version?: (number|null);

            /** IdentityRecord address */
            address?: (string|null);

            /** IdentityRecord ed25519PublicKey */
            ed25519PublicKey?: (Uint8Array|null);

            /** IdentityRecord x25519PublicKey */
            x25519PublicKey?: (Uint8Array|null);

            /** IdentityRecord createdAt */
            createdAt?: (number|Long|null);

            /** IdentityRecord expiresAt */
            expiresAt?: (number|Long|null);

            /** IdentityRecord relayHints */
            relayHints?: (string[]|null);

            /** IdentityRecord verificationTier */
            verificationTier?: (dmcn.identity.VerificationTier|null);

            /** IdentityRecord attestations */
            attestations?: (dmcn.identity.IAttestationRecord[]|null);

            /** IdentityRecord selfSignature */
            selfSignature?: (Uint8Array|null);

            /** IdentityRecord requireOnion */
            requireOnion?: (boolean|null);

            /** IdentityRecord addressCredential */
            addressCredential?: (dmcn.identity.ICredential|null);

            /** IdentityRecord routingCredential */
            routingCredential?: (dmcn.identity.ICredential|null);

            /** IdentityRecord revision */
            revision?: (number|Long|null);

            /** IdentityRecord operatorCredentials */
            operatorCredentials?: (dmcn.identity.ICredential[]|null);
        }

        /** Represents an IdentityRecord. */
        class IdentityRecord implements IIdentityRecord {

            /**
             * Constructs a new IdentityRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IIdentityRecord);

            /** IdentityRecord version. */
            public version: number;

            /** IdentityRecord address. */
            public address: string;

            /** IdentityRecord ed25519PublicKey. */
            public ed25519PublicKey: Uint8Array;

            /** IdentityRecord x25519PublicKey. */
            public x25519PublicKey: Uint8Array;

            /** IdentityRecord createdAt. */
            public createdAt: (number|Long);

            /** IdentityRecord expiresAt. */
            public expiresAt: (number|Long);

            /** IdentityRecord relayHints. */
            public relayHints: string[];

            /** IdentityRecord verificationTier. */
            public verificationTier: dmcn.identity.VerificationTier;

            /** IdentityRecord attestations. */
            public attestations: dmcn.identity.IAttestationRecord[];

            /** IdentityRecord selfSignature. */
            public selfSignature: Uint8Array;

            /** IdentityRecord requireOnion. */
            public requireOnion: boolean;

            /** IdentityRecord addressCredential. */
            public addressCredential?: (dmcn.identity.ICredential|null);

            /** IdentityRecord routingCredential. */
            public routingCredential?: (dmcn.identity.ICredential|null);

            /** IdentityRecord revision. */
            public revision: (number|Long);

            /** IdentityRecord operatorCredentials. */
            public operatorCredentials: dmcn.identity.ICredential[];

            /**
             * Creates a new IdentityRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns IdentityRecord instance
             */
            public static create(properties?: dmcn.identity.IIdentityRecord): dmcn.identity.IdentityRecord;

            /**
             * Encodes the specified IdentityRecord message. Does not implicitly {@link dmcn.identity.IdentityRecord.verify|verify} messages.
             * @param message IdentityRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IIdentityRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified IdentityRecord message, length delimited. Does not implicitly {@link dmcn.identity.IdentityRecord.verify|verify} messages.
             * @param message IdentityRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IIdentityRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an IdentityRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns IdentityRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.IdentityRecord;

            /**
             * Decodes an IdentityRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns IdentityRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.IdentityRecord;

            /**
             * Verifies an IdentityRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an IdentityRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns IdentityRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.IdentityRecord;

            /**
             * Creates a plain object from an IdentityRecord message. Also converts values to other types if specified.
             * @param message IdentityRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.IdentityRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this IdentityRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for IdentityRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an AuthorityKey. */
        interface IAuthorityKey {

            /** AuthorityKey ed25519PublicKey */
            ed25519PublicKey?: (Uint8Array|null);

            /** AuthorityKey x25519PublicKey */
            x25519PublicKey?: (Uint8Array|null);

            /** AuthorityKey effectiveFrom */
            effectiveFrom?: (number|Long|null);

            /** AuthorityKey rotationReason */
            rotationReason?: (number|null);
        }

        /** Represents an AuthorityKey. */
        class AuthorityKey implements IAuthorityKey {

            /**
             * Constructs a new AuthorityKey.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IAuthorityKey);

            /** AuthorityKey ed25519PublicKey. */
            public ed25519PublicKey: Uint8Array;

            /** AuthorityKey x25519PublicKey. */
            public x25519PublicKey: Uint8Array;

            /** AuthorityKey effectiveFrom. */
            public effectiveFrom: (number|Long);

            /** AuthorityKey rotationReason. */
            public rotationReason: number;

            /**
             * Creates a new AuthorityKey instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AuthorityKey instance
             */
            public static create(properties?: dmcn.identity.IAuthorityKey): dmcn.identity.AuthorityKey;

            /**
             * Encodes the specified AuthorityKey message. Does not implicitly {@link dmcn.identity.AuthorityKey.verify|verify} messages.
             * @param message AuthorityKey message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IAuthorityKey, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified AuthorityKey message, length delimited. Does not implicitly {@link dmcn.identity.AuthorityKey.verify|verify} messages.
             * @param message AuthorityKey message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IAuthorityKey, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AuthorityKey message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns AuthorityKey
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.AuthorityKey;

            /**
             * Decodes an AuthorityKey message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns AuthorityKey
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.AuthorityKey;

            /**
             * Verifies an AuthorityKey message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an AuthorityKey message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns AuthorityKey
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.AuthorityKey;

            /**
             * Creates a plain object from an AuthorityKey message. Also converts values to other types if specified.
             * @param message AuthorityKey
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.AuthorityKey, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this AuthorityKey to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for AuthorityKey
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a DomainAuthorityRecord. */
        interface IDomainAuthorityRecord {

            /** DomainAuthorityRecord version */
            version?: (number|null);

            /** DomainAuthorityRecord domain */
            domain?: (string|null);

            /** DomainAuthorityRecord authorityEd25519PublicKey */
            authorityEd25519PublicKey?: (Uint8Array|null);

            /** DomainAuthorityRecord authorityX25519PublicKey */
            authorityX25519PublicKey?: (Uint8Array|null);

            /** DomainAuthorityRecord authorityEffectiveFrom */
            authorityEffectiveFrom?: (number|Long|null);

            /** DomainAuthorityRecord supersededKeys */
            supersededKeys?: (dmcn.identity.IAuthorityKey[]|null);

            /** DomainAuthorityRecord policyFlags */
            policyFlags?: (number|null);

            /** DomainAuthorityRecord createdAt */
            createdAt?: (number|Long|null);

            /** DomainAuthorityRecord revision */
            revision?: (number|Long|null);

            /** DomainAuthorityRecord selfSignature */
            selfSignature?: (Uint8Array|null);

            /** DomainAuthorityRecord authorityCredentials */
            authorityCredentials?: (dmcn.identity.ICredential[]|null);

            /** DomainAuthorityRecord reservedLocalParts */
            reservedLocalParts?: (string[]|null);

            /** DomainAuthorityRecord fleetDomain */
            fleetDomain?: (string|null);
        }

        /** Represents a DomainAuthorityRecord. */
        class DomainAuthorityRecord implements IDomainAuthorityRecord {

            /**
             * Constructs a new DomainAuthorityRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IDomainAuthorityRecord);

            /** DomainAuthorityRecord version. */
            public version: number;

            /** DomainAuthorityRecord domain. */
            public domain: string;

            /** DomainAuthorityRecord authorityEd25519PublicKey. */
            public authorityEd25519PublicKey: Uint8Array;

            /** DomainAuthorityRecord authorityX25519PublicKey. */
            public authorityX25519PublicKey: Uint8Array;

            /** DomainAuthorityRecord authorityEffectiveFrom. */
            public authorityEffectiveFrom: (number|Long);

            /** DomainAuthorityRecord supersededKeys. */
            public supersededKeys: dmcn.identity.IAuthorityKey[];

            /** DomainAuthorityRecord policyFlags. */
            public policyFlags: number;

            /** DomainAuthorityRecord createdAt. */
            public createdAt: (number|Long);

            /** DomainAuthorityRecord revision. */
            public revision: (number|Long);

            /** DomainAuthorityRecord selfSignature. */
            public selfSignature: Uint8Array;

            /** DomainAuthorityRecord authorityCredentials. */
            public authorityCredentials: dmcn.identity.ICredential[];

            /** DomainAuthorityRecord reservedLocalParts. */
            public reservedLocalParts: string[];

            /** DomainAuthorityRecord fleetDomain. */
            public fleetDomain: string;

            /**
             * Creates a new DomainAuthorityRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns DomainAuthorityRecord instance
             */
            public static create(properties?: dmcn.identity.IDomainAuthorityRecord): dmcn.identity.DomainAuthorityRecord;

            /**
             * Encodes the specified DomainAuthorityRecord message. Does not implicitly {@link dmcn.identity.DomainAuthorityRecord.verify|verify} messages.
             * @param message DomainAuthorityRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IDomainAuthorityRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified DomainAuthorityRecord message, length delimited. Does not implicitly {@link dmcn.identity.DomainAuthorityRecord.verify|verify} messages.
             * @param message DomainAuthorityRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IDomainAuthorityRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a DomainAuthorityRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns DomainAuthorityRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.DomainAuthorityRecord;

            /**
             * Decodes a DomainAuthorityRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns DomainAuthorityRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.DomainAuthorityRecord;

            /**
             * Verifies a DomainAuthorityRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a DomainAuthorityRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns DomainAuthorityRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.DomainAuthorityRecord;

            /**
             * Creates a plain object from a DomainAuthorityRecord message. Also converts values to other types if specified.
             * @param message DomainAuthorityRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.DomainAuthorityRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this DomainAuthorityRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for DomainAuthorityRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FleetNode. */
        interface IFleetNode {

            /** FleetNode peerId */
            peerId?: (string|null);

            /** FleetNode multiaddrs */
            multiaddrs?: (string[]|null);

            /** FleetNode roles */
            roles?: (string[]|null);
        }

        /** Represents a FleetNode. */
        class FleetNode implements IFleetNode {

            /**
             * Constructs a new FleetNode.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IFleetNode);

            /** FleetNode peerId. */
            public peerId: string;

            /** FleetNode multiaddrs. */
            public multiaddrs: string[];

            /** FleetNode roles. */
            public roles: string[];

            /**
             * Creates a new FleetNode instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FleetNode instance
             */
            public static create(properties?: dmcn.identity.IFleetNode): dmcn.identity.FleetNode;

            /**
             * Encodes the specified FleetNode message. Does not implicitly {@link dmcn.identity.FleetNode.verify|verify} messages.
             * @param message FleetNode message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IFleetNode, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FleetNode message, length delimited. Does not implicitly {@link dmcn.identity.FleetNode.verify|verify} messages.
             * @param message FleetNode message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IFleetNode, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FleetNode message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FleetNode
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.FleetNode;

            /**
             * Decodes a FleetNode message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FleetNode
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.FleetNode;

            /**
             * Verifies a FleetNode message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FleetNode message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FleetNode
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.FleetNode;

            /**
             * Creates a plain object from a FleetNode message. Also converts values to other types if specified.
             * @param message FleetNode
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.FleetNode, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FleetNode to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FleetNode
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FleetRoster. */
        interface IFleetRoster {

            /** FleetRoster version */
            version?: (number|null);

            /** FleetRoster fleetDomain */
            fleetDomain?: (string|null);

            /** FleetRoster nodes */
            nodes?: (dmcn.identity.IFleetNode[]|null);

            /** FleetRoster revision */
            revision?: (number|Long|null);

            /** FleetRoster createdAt */
            createdAt?: (number|Long|null);

            /** FleetRoster selfSignature */
            selfSignature?: (Uint8Array|null);
        }

        /** Represents a FleetRoster. */
        class FleetRoster implements IFleetRoster {

            /**
             * Constructs a new FleetRoster.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IFleetRoster);

            /** FleetRoster version. */
            public version: number;

            /** FleetRoster fleetDomain. */
            public fleetDomain: string;

            /** FleetRoster nodes. */
            public nodes: dmcn.identity.IFleetNode[];

            /** FleetRoster revision. */
            public revision: (number|Long);

            /** FleetRoster createdAt. */
            public createdAt: (number|Long);

            /** FleetRoster selfSignature. */
            public selfSignature: Uint8Array;

            /**
             * Creates a new FleetRoster instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FleetRoster instance
             */
            public static create(properties?: dmcn.identity.IFleetRoster): dmcn.identity.FleetRoster;

            /**
             * Encodes the specified FleetRoster message. Does not implicitly {@link dmcn.identity.FleetRoster.verify|verify} messages.
             * @param message FleetRoster message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IFleetRoster, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FleetRoster message, length delimited. Does not implicitly {@link dmcn.identity.FleetRoster.verify|verify} messages.
             * @param message FleetRoster message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IFleetRoster, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FleetRoster message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FleetRoster
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.FleetRoster;

            /**
             * Decodes a FleetRoster message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FleetRoster
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.FleetRoster;

            /**
             * Verifies a FleetRoster message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FleetRoster message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FleetRoster
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.FleetRoster;

            /**
             * Creates a plain object from a FleetRoster message. Also converts values to other types if specified.
             * @param message FleetRoster
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.FleetRoster, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FleetRoster to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FleetRoster
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a Credential. */
        interface ICredential {

            /** Credential version */
            version?: (number|null);

            /** Credential subject */
            subject?: (Uint8Array|null);

            /** Credential domain */
            domain?: (string|null);

            /** Credential address */
            address?: (string|null);

            /** Credential roles */
            roles?: (string[]|null);

            /** Credential grants */
            grants?: (string[]|null);

            /** Credential attributes */
            attributes?: ({ [k: string]: string }|null);

            /** Credential issuedAt */
            issuedAt?: (number|Long|null);

            /** Credential notAfter */
            notAfter?: (number|Long|null);

            /** Credential scope */
            scope?: (string|null);

            /** Credential issuerPub */
            issuerPub?: (Uint8Array|null);

            /** Credential signature */
            signature?: (Uint8Array|null);

            /** Credential relayHints */
            relayHints?: (string[]|null);

            /** Credential effectiveFrom */
            effectiveFrom?: (number|Long|null);
        }

        /** Represents a Credential. */
        class Credential implements ICredential {

            /**
             * Constructs a new Credential.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.ICredential);

            /** Credential version. */
            public version: number;

            /** Credential subject. */
            public subject: Uint8Array;

            /** Credential domain. */
            public domain: string;

            /** Credential address. */
            public address: string;

            /** Credential roles. */
            public roles: string[];

            /** Credential grants. */
            public grants: string[];

            /** Credential attributes. */
            public attributes: { [k: string]: string };

            /** Credential issuedAt. */
            public issuedAt: (number|Long);

            /** Credential notAfter. */
            public notAfter: (number|Long);

            /** Credential scope. */
            public scope: string;

            /** Credential issuerPub. */
            public issuerPub: Uint8Array;

            /** Credential signature. */
            public signature: Uint8Array;

            /** Credential relayHints. */
            public relayHints: string[];

            /** Credential effectiveFrom. */
            public effectiveFrom: (number|Long);

            /**
             * Creates a new Credential instance using the specified properties.
             * @param [properties] Properties to set
             * @returns Credential instance
             */
            public static create(properties?: dmcn.identity.ICredential): dmcn.identity.Credential;

            /**
             * Encodes the specified Credential message. Does not implicitly {@link dmcn.identity.Credential.verify|verify} messages.
             * @param message Credential message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.ICredential, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified Credential message, length delimited. Does not implicitly {@link dmcn.identity.Credential.verify|verify} messages.
             * @param message Credential message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.ICredential, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a Credential message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns Credential
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.Credential;

            /**
             * Decodes a Credential message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns Credential
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.Credential;

            /**
             * Verifies a Credential message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a Credential message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns Credential
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.Credential;

            /**
             * Creates a plain object from a Credential message. Also converts values to other types if specified.
             * @param message Credential
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.Credential, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this Credential to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for Credential
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CredentialBlock. */
        interface ICredentialBlock {

            /** CredentialBlock pubkey */
            pubkey?: (Uint8Array|null);

            /** CredentialBlock effectiveFrom */
            effectiveFrom?: (number|Long|null);

            /** CredentialBlock compromised */
            compromised?: (boolean|null);

            /** CredentialBlock compromisedSince */
            compromisedSince?: (number|Long|null);

            /** CredentialBlock createdAt */
            createdAt?: (number|Long|null);
        }

        /** Represents a CredentialBlock. */
        class CredentialBlock implements ICredentialBlock {

            /**
             * Constructs a new CredentialBlock.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.ICredentialBlock);

            /** CredentialBlock pubkey. */
            public pubkey: Uint8Array;

            /** CredentialBlock effectiveFrom. */
            public effectiveFrom: (number|Long);

            /** CredentialBlock compromised. */
            public compromised: boolean;

            /** CredentialBlock compromisedSince. */
            public compromisedSince: (number|Long);

            /** CredentialBlock createdAt. */
            public createdAt: (number|Long);

            /**
             * Creates a new CredentialBlock instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CredentialBlock instance
             */
            public static create(properties?: dmcn.identity.ICredentialBlock): dmcn.identity.CredentialBlock;

            /**
             * Encodes the specified CredentialBlock message. Does not implicitly {@link dmcn.identity.CredentialBlock.verify|verify} messages.
             * @param message CredentialBlock message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.ICredentialBlock, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CredentialBlock message, length delimited. Does not implicitly {@link dmcn.identity.CredentialBlock.verify|verify} messages.
             * @param message CredentialBlock message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.ICredentialBlock, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CredentialBlock message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CredentialBlock
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.CredentialBlock;

            /**
             * Decodes a CredentialBlock message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CredentialBlock
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.CredentialBlock;

            /**
             * Verifies a CredentialBlock message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CredentialBlock message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CredentialBlock
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.CredentialBlock;

            /**
             * Creates a plain object from a CredentialBlock message. Also converts values to other types if specified.
             * @param message CredentialBlock
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.CredentialBlock, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CredentialBlock to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CredentialBlock
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CredentialBlockList. */
        interface ICredentialBlockList {

            /** CredentialBlockList domain */
            domain?: (string|null);

            /** CredentialBlockList blocks */
            blocks?: (dmcn.identity.ICredentialBlock[]|null);

            /** CredentialBlockList revision */
            revision?: (number|Long|null);

            /** CredentialBlockList signature */
            signature?: (Uint8Array|null);
        }

        /** Represents a CredentialBlockList. */
        class CredentialBlockList implements ICredentialBlockList {

            /**
             * Constructs a new CredentialBlockList.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.ICredentialBlockList);

            /** CredentialBlockList domain. */
            public domain: string;

            /** CredentialBlockList blocks. */
            public blocks: dmcn.identity.ICredentialBlock[];

            /** CredentialBlockList revision. */
            public revision: (number|Long);

            /** CredentialBlockList signature. */
            public signature: Uint8Array;

            /**
             * Creates a new CredentialBlockList instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CredentialBlockList instance
             */
            public static create(properties?: dmcn.identity.ICredentialBlockList): dmcn.identity.CredentialBlockList;

            /**
             * Encodes the specified CredentialBlockList message. Does not implicitly {@link dmcn.identity.CredentialBlockList.verify|verify} messages.
             * @param message CredentialBlockList message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.ICredentialBlockList, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CredentialBlockList message, length delimited. Does not implicitly {@link dmcn.identity.CredentialBlockList.verify|verify} messages.
             * @param message CredentialBlockList message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.ICredentialBlockList, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CredentialBlockList message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CredentialBlockList
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.CredentialBlockList;

            /**
             * Decodes a CredentialBlockList message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CredentialBlockList
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.CredentialBlockList;

            /**
             * Verifies a CredentialBlockList message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CredentialBlockList message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CredentialBlockList
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.CredentialBlockList;

            /**
             * Creates a plain object from a CredentialBlockList message. Also converts values to other types if specified.
             * @param message CredentialBlockList
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.CredentialBlockList, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CredentialBlockList to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CredentialBlockList
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CredentialBundle. */
        interface ICredentialBundle {

            /** CredentialBundle credential */
            credential?: (dmcn.identity.ICredential|null);

            /** CredentialBundle dar */
            dar?: (dmcn.identity.IDomainAuthorityRecord|null);
        }

        /** Represents a CredentialBundle. */
        class CredentialBundle implements ICredentialBundle {

            /**
             * Constructs a new CredentialBundle.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.ICredentialBundle);

            /** CredentialBundle credential. */
            public credential?: (dmcn.identity.ICredential|null);

            /** CredentialBundle dar. */
            public dar?: (dmcn.identity.IDomainAuthorityRecord|null);

            /**
             * Creates a new CredentialBundle instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CredentialBundle instance
             */
            public static create(properties?: dmcn.identity.ICredentialBundle): dmcn.identity.CredentialBundle;

            /**
             * Encodes the specified CredentialBundle message. Does not implicitly {@link dmcn.identity.CredentialBundle.verify|verify} messages.
             * @param message CredentialBundle message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.ICredentialBundle, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CredentialBundle message, length delimited. Does not implicitly {@link dmcn.identity.CredentialBundle.verify|verify} messages.
             * @param message CredentialBundle message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.ICredentialBundle, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CredentialBundle message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CredentialBundle
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.CredentialBundle;

            /**
             * Decodes a CredentialBundle message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CredentialBundle
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.CredentialBundle;

            /**
             * Verifies a CredentialBundle message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CredentialBundle message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CredentialBundle
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.CredentialBundle;

            /**
             * Creates a plain object from a CredentialBundle message. Also converts values to other types if specified.
             * @param message CredentialBundle
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.CredentialBundle, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CredentialBundle to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CredentialBundle
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a JoinRequest. */
        interface IJoinRequest {

            /** JoinRequest credential */
            credential?: (dmcn.identity.ICredential|null);

            /** JoinRequest dar */
            dar?: (dmcn.identity.IDomainAuthorityRecord|null);

            /** JoinRequest bundles */
            bundles?: (dmcn.identity.ICredentialBundle[]|null);
        }

        /** Represents a JoinRequest. */
        class JoinRequest implements IJoinRequest {

            /**
             * Constructs a new JoinRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IJoinRequest);

            /** JoinRequest credential. */
            public credential?: (dmcn.identity.ICredential|null);

            /** JoinRequest dar. */
            public dar?: (dmcn.identity.IDomainAuthorityRecord|null);

            /** JoinRequest bundles. */
            public bundles: dmcn.identity.ICredentialBundle[];

            /**
             * Creates a new JoinRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns JoinRequest instance
             */
            public static create(properties?: dmcn.identity.IJoinRequest): dmcn.identity.JoinRequest;

            /**
             * Encodes the specified JoinRequest message. Does not implicitly {@link dmcn.identity.JoinRequest.verify|verify} messages.
             * @param message JoinRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IJoinRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified JoinRequest message, length delimited. Does not implicitly {@link dmcn.identity.JoinRequest.verify|verify} messages.
             * @param message JoinRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IJoinRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a JoinRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns JoinRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.JoinRequest;

            /**
             * Decodes a JoinRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns JoinRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.JoinRequest;

            /**
             * Verifies a JoinRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a JoinRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns JoinRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.JoinRequest;

            /**
             * Creates a plain object from a JoinRequest message. Also converts values to other types if specified.
             * @param message JoinRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.JoinRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this JoinRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for JoinRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a JoinResponse. */
        interface IJoinResponse {

            /** JoinResponse accepted */
            accepted?: (boolean|null);

            /** JoinResponse error */
            error?: (string|null);

            /** JoinResponse credential */
            credential?: (dmcn.identity.ICredential|null);

            /** JoinResponse dar */
            dar?: (dmcn.identity.IDomainAuthorityRecord|null);

            /** JoinResponse bundles */
            bundles?: (dmcn.identity.ICredentialBundle[]|null);
        }

        /** Represents a JoinResponse. */
        class JoinResponse implements IJoinResponse {

            /**
             * Constructs a new JoinResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IJoinResponse);

            /** JoinResponse accepted. */
            public accepted: boolean;

            /** JoinResponse error. */
            public error: string;

            /** JoinResponse credential. */
            public credential?: (dmcn.identity.ICredential|null);

            /** JoinResponse dar. */
            public dar?: (dmcn.identity.IDomainAuthorityRecord|null);

            /** JoinResponse bundles. */
            public bundles: dmcn.identity.ICredentialBundle[];

            /**
             * Creates a new JoinResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns JoinResponse instance
             */
            public static create(properties?: dmcn.identity.IJoinResponse): dmcn.identity.JoinResponse;

            /**
             * Encodes the specified JoinResponse message. Does not implicitly {@link dmcn.identity.JoinResponse.verify|verify} messages.
             * @param message JoinResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IJoinResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified JoinResponse message, length delimited. Does not implicitly {@link dmcn.identity.JoinResponse.verify|verify} messages.
             * @param message JoinResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IJoinResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a JoinResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns JoinResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.JoinResponse;

            /**
             * Decodes a JoinResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns JoinResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.JoinResponse;

            /**
             * Verifies a JoinResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a JoinResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns JoinResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.JoinResponse;

            /**
             * Creates a plain object from a JoinResponse message. Also converts values to other types if specified.
             * @param message JoinResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.JoinResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this JoinResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for JoinResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a RemovedBinding. */
        interface IRemovedBinding {

            /** RemovedBinding ed25519PublicKey */
            ed25519PublicKey?: (Uint8Array|null);

            /** RemovedBinding removedAt */
            removedAt?: (number|Long|null);
        }

        /** Represents a RemovedBinding. */
        class RemovedBinding implements IRemovedBinding {

            /**
             * Constructs a new RemovedBinding.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IRemovedBinding);

            /** RemovedBinding ed25519PublicKey. */
            public ed25519PublicKey: Uint8Array;

            /** RemovedBinding removedAt. */
            public removedAt: (number|Long);

            /**
             * Creates a new RemovedBinding instance using the specified properties.
             * @param [properties] Properties to set
             * @returns RemovedBinding instance
             */
            public static create(properties?: dmcn.identity.IRemovedBinding): dmcn.identity.RemovedBinding;

            /**
             * Encodes the specified RemovedBinding message. Does not implicitly {@link dmcn.identity.RemovedBinding.verify|verify} messages.
             * @param message RemovedBinding message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IRemovedBinding, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified RemovedBinding message, length delimited. Does not implicitly {@link dmcn.identity.RemovedBinding.verify|verify} messages.
             * @param message RemovedBinding message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IRemovedBinding, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a RemovedBinding message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns RemovedBinding
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.RemovedBinding;

            /**
             * Decodes a RemovedBinding message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns RemovedBinding
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.RemovedBinding;

            /**
             * Verifies a RemovedBinding message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a RemovedBinding message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns RemovedBinding
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.RemovedBinding;

            /**
             * Creates a plain object from a RemovedBinding message. Also converts values to other types if specified.
             * @param message RemovedBinding
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.RemovedBinding, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this RemovedBinding to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for RemovedBinding
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an AddressRemovalRecord. */
        interface IAddressRemovalRecord {

            /** AddressRemovalRecord version */
            version?: (number|null);

            /** AddressRemovalRecord domain */
            domain?: (string|null);

            /** AddressRemovalRecord address */
            address?: (string|null);

            /** AddressRemovalRecord removedBindings */
            removedBindings?: (dmcn.identity.IRemovedBinding[]|null);

            /** AddressRemovalRecord revision */
            revision?: (number|Long|null);

            /** AddressRemovalRecord createdAt */
            createdAt?: (number|Long|null);

            /** AddressRemovalRecord selfSignature */
            selfSignature?: (Uint8Array|null);
        }

        /** Represents an AddressRemovalRecord. */
        class AddressRemovalRecord implements IAddressRemovalRecord {

            /**
             * Constructs a new AddressRemovalRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IAddressRemovalRecord);

            /** AddressRemovalRecord version. */
            public version: number;

            /** AddressRemovalRecord domain. */
            public domain: string;

            /** AddressRemovalRecord address. */
            public address: string;

            /** AddressRemovalRecord removedBindings. */
            public removedBindings: dmcn.identity.IRemovedBinding[];

            /** AddressRemovalRecord revision. */
            public revision: (number|Long);

            /** AddressRemovalRecord createdAt. */
            public createdAt: (number|Long);

            /** AddressRemovalRecord selfSignature. */
            public selfSignature: Uint8Array;

            /**
             * Creates a new AddressRemovalRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AddressRemovalRecord instance
             */
            public static create(properties?: dmcn.identity.IAddressRemovalRecord): dmcn.identity.AddressRemovalRecord;

            /**
             * Encodes the specified AddressRemovalRecord message. Does not implicitly {@link dmcn.identity.AddressRemovalRecord.verify|verify} messages.
             * @param message AddressRemovalRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IAddressRemovalRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified AddressRemovalRecord message, length delimited. Does not implicitly {@link dmcn.identity.AddressRemovalRecord.verify|verify} messages.
             * @param message AddressRemovalRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IAddressRemovalRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AddressRemovalRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns AddressRemovalRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.AddressRemovalRecord;

            /**
             * Decodes an AddressRemovalRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns AddressRemovalRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.AddressRemovalRecord;

            /**
             * Verifies an AddressRemovalRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an AddressRemovalRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns AddressRemovalRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.AddressRemovalRecord;

            /**
             * Creates a plain object from an AddressRemovalRecord message. Also converts values to other types if specified.
             * @param message AddressRemovalRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.AddressRemovalRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this AddressRemovalRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for AddressRemovalRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a CompromisedKey. */
        interface ICompromisedKey {

            /** CompromisedKey ed25519PublicKey */
            ed25519PublicKey?: (Uint8Array|null);

            /** CompromisedKey compromisedAt */
            compromisedAt?: (number|Long|null);

            /** CompromisedKey retentionUntil */
            retentionUntil?: (number|Long|null);
        }

        /** Represents a CompromisedKey. */
        class CompromisedKey implements ICompromisedKey {

            /**
             * Constructs a new CompromisedKey.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.ICompromisedKey);

            /** CompromisedKey ed25519PublicKey. */
            public ed25519PublicKey: Uint8Array;

            /** CompromisedKey compromisedAt. */
            public compromisedAt: (number|Long);

            /** CompromisedKey retentionUntil. */
            public retentionUntil: (number|Long);

            /**
             * Creates a new CompromisedKey instance using the specified properties.
             * @param [properties] Properties to set
             * @returns CompromisedKey instance
             */
            public static create(properties?: dmcn.identity.ICompromisedKey): dmcn.identity.CompromisedKey;

            /**
             * Encodes the specified CompromisedKey message. Does not implicitly {@link dmcn.identity.CompromisedKey.verify|verify} messages.
             * @param message CompromisedKey message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.ICompromisedKey, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified CompromisedKey message, length delimited. Does not implicitly {@link dmcn.identity.CompromisedKey.verify|verify} messages.
             * @param message CompromisedKey message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.ICompromisedKey, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a CompromisedKey message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns CompromisedKey
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.CompromisedKey;

            /**
             * Decodes a CompromisedKey message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns CompromisedKey
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.CompromisedKey;

            /**
             * Verifies a CompromisedKey message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a CompromisedKey message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns CompromisedKey
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.CompromisedKey;

            /**
             * Creates a plain object from a CompromisedKey message. Also converts values to other types if specified.
             * @param message CompromisedKey
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.CompromisedKey, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this CompromisedKey to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for CompromisedKey
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a RelayDescriptor. */
        interface IRelayDescriptor {

            /** RelayDescriptor peerId */
            peerId?: (string|null);

            /** RelayDescriptor x25519PublicKey */
            x25519PublicKey?: (Uint8Array|null);

            /** RelayDescriptor multiaddrs */
            multiaddrs?: (string[]|null);

            /** RelayDescriptor createdAt */
            createdAt?: (number|Long|null);

            /** RelayDescriptor revision */
            revision?: (number|Long|null);

            /** RelayDescriptor signature */
            signature?: (Uint8Array|null);

            /** RelayDescriptor domain */
            domain?: (string|null);

            /** RelayDescriptor credential */
            credential?: (dmcn.identity.ICredential|null);
        }

        /** Represents a RelayDescriptor. */
        class RelayDescriptor implements IRelayDescriptor {

            /**
             * Constructs a new RelayDescriptor.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IRelayDescriptor);

            /** RelayDescriptor peerId. */
            public peerId: string;

            /** RelayDescriptor x25519PublicKey. */
            public x25519PublicKey: Uint8Array;

            /** RelayDescriptor multiaddrs. */
            public multiaddrs: string[];

            /** RelayDescriptor createdAt. */
            public createdAt: (number|Long);

            /** RelayDescriptor revision. */
            public revision: (number|Long);

            /** RelayDescriptor signature. */
            public signature: Uint8Array;

            /** RelayDescriptor domain. */
            public domain: string;

            /** RelayDescriptor credential. */
            public credential?: (dmcn.identity.ICredential|null);

            /**
             * Creates a new RelayDescriptor instance using the specified properties.
             * @param [properties] Properties to set
             * @returns RelayDescriptor instance
             */
            public static create(properties?: dmcn.identity.IRelayDescriptor): dmcn.identity.RelayDescriptor;

            /**
             * Encodes the specified RelayDescriptor message. Does not implicitly {@link dmcn.identity.RelayDescriptor.verify|verify} messages.
             * @param message RelayDescriptor message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IRelayDescriptor, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified RelayDescriptor message, length delimited. Does not implicitly {@link dmcn.identity.RelayDescriptor.verify|verify} messages.
             * @param message RelayDescriptor message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IRelayDescriptor, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a RelayDescriptor message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns RelayDescriptor
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.RelayDescriptor;

            /**
             * Decodes a RelayDescriptor message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns RelayDescriptor
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.RelayDescriptor;

            /**
             * Verifies a RelayDescriptor message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a RelayDescriptor message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns RelayDescriptor
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.RelayDescriptor;

            /**
             * Creates a plain object from a RelayDescriptor message. Also converts values to other types if specified.
             * @param message RelayDescriptor
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.RelayDescriptor, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this RelayDescriptor to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for RelayDescriptor
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a KeyCompromiseRecord. */
        interface IKeyCompromiseRecord {

            /** KeyCompromiseRecord version */
            version?: (number|null);

            /** KeyCompromiseRecord domain */
            domain?: (string|null);

            /** KeyCompromiseRecord compromisedKeys */
            compromisedKeys?: (dmcn.identity.ICompromisedKey[]|null);

            /** KeyCompromiseRecord revision */
            revision?: (number|Long|null);

            /** KeyCompromiseRecord createdAt */
            createdAt?: (number|Long|null);

            /** KeyCompromiseRecord selfSignature */
            selfSignature?: (Uint8Array|null);
        }

        /** Represents a KeyCompromiseRecord. */
        class KeyCompromiseRecord implements IKeyCompromiseRecord {

            /**
             * Constructs a new KeyCompromiseRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.identity.IKeyCompromiseRecord);

            /** KeyCompromiseRecord version. */
            public version: number;

            /** KeyCompromiseRecord domain. */
            public domain: string;

            /** KeyCompromiseRecord compromisedKeys. */
            public compromisedKeys: dmcn.identity.ICompromisedKey[];

            /** KeyCompromiseRecord revision. */
            public revision: (number|Long);

            /** KeyCompromiseRecord createdAt. */
            public createdAt: (number|Long);

            /** KeyCompromiseRecord selfSignature. */
            public selfSignature: Uint8Array;

            /**
             * Creates a new KeyCompromiseRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns KeyCompromiseRecord instance
             */
            public static create(properties?: dmcn.identity.IKeyCompromiseRecord): dmcn.identity.KeyCompromiseRecord;

            /**
             * Encodes the specified KeyCompromiseRecord message. Does not implicitly {@link dmcn.identity.KeyCompromiseRecord.verify|verify} messages.
             * @param message KeyCompromiseRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.identity.IKeyCompromiseRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified KeyCompromiseRecord message, length delimited. Does not implicitly {@link dmcn.identity.KeyCompromiseRecord.verify|verify} messages.
             * @param message KeyCompromiseRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.identity.IKeyCompromiseRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a KeyCompromiseRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns KeyCompromiseRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.identity.KeyCompromiseRecord;

            /**
             * Decodes a KeyCompromiseRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns KeyCompromiseRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.identity.KeyCompromiseRecord;

            /**
             * Verifies a KeyCompromiseRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a KeyCompromiseRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns KeyCompromiseRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.identity.KeyCompromiseRecord;

            /**
             * Creates a plain object from a KeyCompromiseRecord message. Also converts values to other types if specified.
             * @param message KeyCompromiseRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.identity.KeyCompromiseRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this KeyCompromiseRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for KeyCompromiseRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }
    }

    /** Namespace message. */
    namespace message {

        /** Properties of a MessageBody. */
        interface IMessageBody {

            /** MessageBody contentType */
            contentType?: (string|null);

            /** MessageBody content */
            content?: (Uint8Array|null);
        }

        /** Represents a MessageBody. */
        class MessageBody implements IMessageBody {

            /**
             * Constructs a new MessageBody.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IMessageBody);

            /** MessageBody contentType. */
            public contentType: string;

            /** MessageBody content. */
            public content: Uint8Array;

            /**
             * Creates a new MessageBody instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MessageBody instance
             */
            public static create(properties?: dmcn.message.IMessageBody): dmcn.message.MessageBody;

            /**
             * Encodes the specified MessageBody message. Does not implicitly {@link dmcn.message.MessageBody.verify|verify} messages.
             * @param message MessageBody message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IMessageBody, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MessageBody message, length delimited. Does not implicitly {@link dmcn.message.MessageBody.verify|verify} messages.
             * @param message MessageBody message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IMessageBody, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MessageBody message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MessageBody
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.MessageBody;

            /**
             * Decodes a MessageBody message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MessageBody
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.MessageBody;

            /**
             * Verifies a MessageBody message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MessageBody message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MessageBody
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.MessageBody;

            /**
             * Creates a plain object from a MessageBody message. Also converts values to other types if specified.
             * @param message MessageBody
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.MessageBody, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MessageBody to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MessageBody
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an AttachmentRecord. */
        interface IAttachmentRecord {

            /** AttachmentRecord attachmentId */
            attachmentId?: (Uint8Array|null);

            /** AttachmentRecord filename */
            filename?: (string|null);

            /** AttachmentRecord contentType */
            contentType?: (string|null);

            /** AttachmentRecord sizeBytes */
            sizeBytes?: (number|Long|null);

            /** AttachmentRecord contentHash */
            contentHash?: (Uint8Array|null);

            /** AttachmentRecord content */
            content?: (Uint8Array|null);

            /** AttachmentRecord contentId */
            contentId?: (string|null);

            /** AttachmentRecord disposition */
            disposition?: (string|null);
        }

        /** Represents an AttachmentRecord. */
        class AttachmentRecord implements IAttachmentRecord {

            /**
             * Constructs a new AttachmentRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IAttachmentRecord);

            /** AttachmentRecord attachmentId. */
            public attachmentId: Uint8Array;

            /** AttachmentRecord filename. */
            public filename: string;

            /** AttachmentRecord contentType. */
            public contentType: string;

            /** AttachmentRecord sizeBytes. */
            public sizeBytes: (number|Long);

            /** AttachmentRecord contentHash. */
            public contentHash: Uint8Array;

            /** AttachmentRecord content. */
            public content: Uint8Array;

            /** AttachmentRecord contentId. */
            public contentId: string;

            /** AttachmentRecord disposition. */
            public disposition: string;

            /**
             * Creates a new AttachmentRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AttachmentRecord instance
             */
            public static create(properties?: dmcn.message.IAttachmentRecord): dmcn.message.AttachmentRecord;

            /**
             * Encodes the specified AttachmentRecord message. Does not implicitly {@link dmcn.message.AttachmentRecord.verify|verify} messages.
             * @param message AttachmentRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IAttachmentRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified AttachmentRecord message, length delimited. Does not implicitly {@link dmcn.message.AttachmentRecord.verify|verify} messages.
             * @param message AttachmentRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IAttachmentRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AttachmentRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns AttachmentRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.AttachmentRecord;

            /**
             * Decodes an AttachmentRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns AttachmentRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.AttachmentRecord;

            /**
             * Verifies an AttachmentRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an AttachmentRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns AttachmentRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.AttachmentRecord;

            /**
             * Creates a plain object from an AttachmentRecord message. Also converts values to other types if specified.
             * @param message AttachmentRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.AttachmentRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this AttachmentRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for AttachmentRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a PlaintextMessage. */
        interface IPlaintextMessage {

            /** PlaintextMessage version */
            version?: (number|null);

            /** PlaintextMessage messageId */
            messageId?: (Uint8Array|null);

            /** PlaintextMessage threadId */
            threadId?: (Uint8Array|null);

            /** PlaintextMessage senderAddress */
            senderAddress?: (string|null);

            /** PlaintextMessage senderPublicKey */
            senderPublicKey?: (Uint8Array|null);

            /** PlaintextMessage recipientAddress */
            recipientAddress?: (string|null);

            /** PlaintextMessage sentAt */
            sentAt?: (number|Long|null);

            /** PlaintextMessage subject */
            subject?: (string|null);

            /** PlaintextMessage body */
            body?: (dmcn.message.IMessageBody|null);

            /** PlaintextMessage attachments */
            attachments?: (dmcn.message.IAttachmentRecord[]|null);

            /** PlaintextMessage replyToId */
            replyToId?: (Uint8Array|null);

            /** PlaintextMessage alternatives */
            alternatives?: (dmcn.message.IMessageBody[]|null);

            /** PlaintextMessage senderDisplay */
            senderDisplay?: (string|null);
        }

        /** Represents a PlaintextMessage. */
        class PlaintextMessage implements IPlaintextMessage {

            /**
             * Constructs a new PlaintextMessage.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IPlaintextMessage);

            /** PlaintextMessage version. */
            public version: number;

            /** PlaintextMessage messageId. */
            public messageId: Uint8Array;

            /** PlaintextMessage threadId. */
            public threadId: Uint8Array;

            /** PlaintextMessage senderAddress. */
            public senderAddress: string;

            /** PlaintextMessage senderPublicKey. */
            public senderPublicKey: Uint8Array;

            /** PlaintextMessage recipientAddress. */
            public recipientAddress: string;

            /** PlaintextMessage sentAt. */
            public sentAt: (number|Long);

            /** PlaintextMessage subject. */
            public subject: string;

            /** PlaintextMessage body. */
            public body?: (dmcn.message.IMessageBody|null);

            /** PlaintextMessage attachments. */
            public attachments: dmcn.message.IAttachmentRecord[];

            /** PlaintextMessage replyToId. */
            public replyToId: Uint8Array;

            /** PlaintextMessage alternatives. */
            public alternatives: dmcn.message.IMessageBody[];

            /** PlaintextMessage senderDisplay. */
            public senderDisplay: string;

            /**
             * Creates a new PlaintextMessage instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PlaintextMessage instance
             */
            public static create(properties?: dmcn.message.IPlaintextMessage): dmcn.message.PlaintextMessage;

            /**
             * Encodes the specified PlaintextMessage message. Does not implicitly {@link dmcn.message.PlaintextMessage.verify|verify} messages.
             * @param message PlaintextMessage message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IPlaintextMessage, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PlaintextMessage message, length delimited. Does not implicitly {@link dmcn.message.PlaintextMessage.verify|verify} messages.
             * @param message PlaintextMessage message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IPlaintextMessage, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PlaintextMessage message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PlaintextMessage
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.PlaintextMessage;

            /**
             * Decodes a PlaintextMessage message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PlaintextMessage
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.PlaintextMessage;

            /**
             * Verifies a PlaintextMessage message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PlaintextMessage message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PlaintextMessage
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.PlaintextMessage;

            /**
             * Creates a plain object from a PlaintextMessage message. Also converts values to other types if specified.
             * @param message PlaintextMessage
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.PlaintextMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PlaintextMessage to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PlaintextMessage
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a SignedMessage. */
        interface ISignedMessage {

            /** SignedMessage plaintext */
            plaintext?: (dmcn.message.IPlaintextMessage|null);

            /** SignedMessage senderSignature */
            senderSignature?: (Uint8Array|null);
        }

        /** Represents a SignedMessage. */
        class SignedMessage implements ISignedMessage {

            /**
             * Constructs a new SignedMessage.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.ISignedMessage);

            /** SignedMessage plaintext. */
            public plaintext?: (dmcn.message.IPlaintextMessage|null);

            /** SignedMessage senderSignature. */
            public senderSignature: Uint8Array;

            /**
             * Creates a new SignedMessage instance using the specified properties.
             * @param [properties] Properties to set
             * @returns SignedMessage instance
             */
            public static create(properties?: dmcn.message.ISignedMessage): dmcn.message.SignedMessage;

            /**
             * Encodes the specified SignedMessage message. Does not implicitly {@link dmcn.message.SignedMessage.verify|verify} messages.
             * @param message SignedMessage message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.ISignedMessage, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified SignedMessage message, length delimited. Does not implicitly {@link dmcn.message.SignedMessage.verify|verify} messages.
             * @param message SignedMessage message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.ISignedMessage, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a SignedMessage message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns SignedMessage
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.SignedMessage;

            /**
             * Decodes a SignedMessage message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns SignedMessage
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.SignedMessage;

            /**
             * Verifies a SignedMessage message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a SignedMessage message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns SignedMessage
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.SignedMessage;

            /**
             * Creates a plain object from a SignedMessage message. Also converts values to other types if specified.
             * @param message SignedMessage
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.SignedMessage, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this SignedMessage to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for SignedMessage
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MessageHeader. */
        interface IMessageHeader {

            /** MessageHeader version */
            version?: (number|null);

            /** MessageHeader messageId */
            messageId?: (Uint8Array|null);

            /** MessageHeader threadId */
            threadId?: (Uint8Array|null);

            /** MessageHeader senderAddress */
            senderAddress?: (string|null);

            /** MessageHeader senderPublicKey */
            senderPublicKey?: (Uint8Array|null);

            /** MessageHeader recipientAddress */
            recipientAddress?: (string|null);

            /** MessageHeader sentAt */
            sentAt?: (number|Long|null);

            /** MessageHeader subject */
            subject?: (string|null);

            /** MessageHeader attachmentCount */
            attachmentCount?: (number|null);

            /** MessageHeader bodySize */
            bodySize?: (number|Long|null);

            /** MessageHeader snippet */
            snippet?: (string|null);

            /** MessageHeader replyToId */
            replyToId?: (Uint8Array|null);

            /** MessageHeader bodyHash */
            bodyHash?: (Uint8Array|null);

            /** MessageHeader bodyContentAddress */
            bodyContentAddress?: (Uint8Array|null);

            /** MessageHeader to */
            to?: (string[]|null);

            /** MessageHeader cc */
            cc?: (string[]|null);

            /** MessageHeader bcc */
            bcc?: (string[]|null);

            /** MessageHeader senderDisplay */
            senderDisplay?: (string|null);
        }

        /** Represents a MessageHeader. */
        class MessageHeader implements IMessageHeader {

            /**
             * Constructs a new MessageHeader.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IMessageHeader);

            /** MessageHeader version. */
            public version: number;

            /** MessageHeader messageId. */
            public messageId: Uint8Array;

            /** MessageHeader threadId. */
            public threadId: Uint8Array;

            /** MessageHeader senderAddress. */
            public senderAddress: string;

            /** MessageHeader senderPublicKey. */
            public senderPublicKey: Uint8Array;

            /** MessageHeader recipientAddress. */
            public recipientAddress: string;

            /** MessageHeader sentAt. */
            public sentAt: (number|Long);

            /** MessageHeader subject. */
            public subject: string;

            /** MessageHeader attachmentCount. */
            public attachmentCount: number;

            /** MessageHeader bodySize. */
            public bodySize: (number|Long);

            /** MessageHeader snippet. */
            public snippet: string;

            /** MessageHeader replyToId. */
            public replyToId: Uint8Array;

            /** MessageHeader bodyHash. */
            public bodyHash: Uint8Array;

            /** MessageHeader bodyContentAddress. */
            public bodyContentAddress: Uint8Array;

            /** MessageHeader to. */
            public to: string[];

            /** MessageHeader cc. */
            public cc: string[];

            /** MessageHeader bcc. */
            public bcc: string[];

            /** MessageHeader senderDisplay. */
            public senderDisplay: string;

            /**
             * Creates a new MessageHeader instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MessageHeader instance
             */
            public static create(properties?: dmcn.message.IMessageHeader): dmcn.message.MessageHeader;

            /**
             * Encodes the specified MessageHeader message. Does not implicitly {@link dmcn.message.MessageHeader.verify|verify} messages.
             * @param message MessageHeader message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IMessageHeader, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MessageHeader message, length delimited. Does not implicitly {@link dmcn.message.MessageHeader.verify|verify} messages.
             * @param message MessageHeader message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IMessageHeader, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MessageHeader message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MessageHeader
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.MessageHeader;

            /**
             * Decodes a MessageHeader message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MessageHeader
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.MessageHeader;

            /**
             * Verifies a MessageHeader message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MessageHeader message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MessageHeader
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.MessageHeader;

            /**
             * Creates a plain object from a MessageHeader message. Also converts values to other types if specified.
             * @param message MessageHeader
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.MessageHeader, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MessageHeader to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MessageHeader
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a SignedHeader. */
        interface ISignedHeader {

            /** SignedHeader header */
            header?: (dmcn.message.IMessageHeader|null);

            /** SignedHeader senderSignature */
            senderSignature?: (Uint8Array|null);
        }

        /** Represents a SignedHeader. */
        class SignedHeader implements ISignedHeader {

            /**
             * Constructs a new SignedHeader.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.ISignedHeader);

            /** SignedHeader header. */
            public header?: (dmcn.message.IMessageHeader|null);

            /** SignedHeader senderSignature. */
            public senderSignature: Uint8Array;

            /**
             * Creates a new SignedHeader instance using the specified properties.
             * @param [properties] Properties to set
             * @returns SignedHeader instance
             */
            public static create(properties?: dmcn.message.ISignedHeader): dmcn.message.SignedHeader;

            /**
             * Encodes the specified SignedHeader message. Does not implicitly {@link dmcn.message.SignedHeader.verify|verify} messages.
             * @param message SignedHeader message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.ISignedHeader, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified SignedHeader message, length delimited. Does not implicitly {@link dmcn.message.SignedHeader.verify|verify} messages.
             * @param message SignedHeader message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.ISignedHeader, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a SignedHeader message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns SignedHeader
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.SignedHeader;

            /**
             * Decodes a SignedHeader message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns SignedHeader
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.SignedHeader;

            /**
             * Verifies a SignedHeader message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a SignedHeader message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns SignedHeader
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.SignedHeader;

            /**
             * Creates a plain object from a SignedHeader message. Also converts values to other types if specified.
             * @param message SignedHeader
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.SignedHeader, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this SignedHeader to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for SignedHeader
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MessageContent. */
        interface IMessageContent {

            /** MessageContent body */
            body?: (dmcn.message.IMessageBody|null);

            /** MessageContent attachments */
            attachments?: (dmcn.message.IAttachmentRecord[]|null);

            /** MessageContent alternatives */
            alternatives?: (dmcn.message.IMessageBody[]|null);
        }

        /** Represents a MessageContent. */
        class MessageContent implements IMessageContent {

            /**
             * Constructs a new MessageContent.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IMessageContent);

            /** MessageContent body. */
            public body?: (dmcn.message.IMessageBody|null);

            /** MessageContent attachments. */
            public attachments: dmcn.message.IAttachmentRecord[];

            /** MessageContent alternatives. */
            public alternatives: dmcn.message.IMessageBody[];

            /**
             * Creates a new MessageContent instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MessageContent instance
             */
            public static create(properties?: dmcn.message.IMessageContent): dmcn.message.MessageContent;

            /**
             * Encodes the specified MessageContent message. Does not implicitly {@link dmcn.message.MessageContent.verify|verify} messages.
             * @param message MessageContent message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IMessageContent, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MessageContent message, length delimited. Does not implicitly {@link dmcn.message.MessageContent.verify|verify} messages.
             * @param message MessageContent message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IMessageContent, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MessageContent message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MessageContent
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.MessageContent;

            /**
             * Decodes a MessageContent message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MessageContent
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.MessageContent;

            /**
             * Verifies a MessageContent message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MessageContent message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MessageContent
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.MessageContent;

            /**
             * Creates a plain object from a MessageContent message. Also converts values to other types if specified.
             * @param message MessageContent
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.MessageContent, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MessageContent to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MessageContent
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a RecipientRecord. */
        interface IRecipientRecord {

            /** RecipientRecord deviceId */
            deviceId?: (Uint8Array|null);

            /** RecipientRecord recipientXPub */
            recipientXPub?: (Uint8Array|null);

            /** RecipientRecord ephemeralXPub */
            ephemeralXPub?: (Uint8Array|null);

            /** RecipientRecord wrappedCek */
            wrappedCek?: (Uint8Array|null);

            /** RecipientRecord cekNonce */
            cekNonce?: (Uint8Array|null);

            /** RecipientRecord cekTag */
            cekTag?: (Uint8Array|null);

            /** RecipientRecord kdf */
            kdf?: (number|null);
        }

        /** Represents a RecipientRecord. */
        class RecipientRecord implements IRecipientRecord {

            /**
             * Constructs a new RecipientRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IRecipientRecord);

            /** RecipientRecord deviceId. */
            public deviceId: Uint8Array;

            /** RecipientRecord recipientXPub. */
            public recipientXPub: Uint8Array;

            /** RecipientRecord ephemeralXPub. */
            public ephemeralXPub: Uint8Array;

            /** RecipientRecord wrappedCek. */
            public wrappedCek: Uint8Array;

            /** RecipientRecord cekNonce. */
            public cekNonce: Uint8Array;

            /** RecipientRecord cekTag. */
            public cekTag: Uint8Array;

            /** RecipientRecord kdf. */
            public kdf: number;

            /**
             * Creates a new RecipientRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns RecipientRecord instance
             */
            public static create(properties?: dmcn.message.IRecipientRecord): dmcn.message.RecipientRecord;

            /**
             * Encodes the specified RecipientRecord message. Does not implicitly {@link dmcn.message.RecipientRecord.verify|verify} messages.
             * @param message RecipientRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IRecipientRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified RecipientRecord message, length delimited. Does not implicitly {@link dmcn.message.RecipientRecord.verify|verify} messages.
             * @param message RecipientRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IRecipientRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a RecipientRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns RecipientRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.RecipientRecord;

            /**
             * Decodes a RecipientRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns RecipientRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.RecipientRecord;

            /**
             * Verifies a RecipientRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a RecipientRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns RecipientRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.RecipientRecord;

            /**
             * Creates a plain object from a RecipientRecord message. Also converts values to other types if specified.
             * @param message RecipientRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.RecipientRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this RecipientRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for RecipientRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an EncryptedEnvelope. */
        interface IEncryptedEnvelope {

            /** EncryptedEnvelope version */
            version?: (number|null);

            /** EncryptedEnvelope messageId */
            messageId?: (Uint8Array|null);

            /** EncryptedEnvelope recipients */
            recipients?: (dmcn.message.IRecipientRecord[]|null);

            /** EncryptedEnvelope encryptedPayload */
            encryptedPayload?: (Uint8Array|null);

            /** EncryptedEnvelope payloadNonce */
            payloadNonce?: (Uint8Array|null);

            /** EncryptedEnvelope payloadTag */
            payloadTag?: (Uint8Array|null);

            /** EncryptedEnvelope payloadSizeClass */
            payloadSizeClass?: (number|null);

            /** EncryptedEnvelope createdAt */
            createdAt?: (number|Long|null);

            /** EncryptedEnvelope ratchetPubKey */
            ratchetPubKey?: (Uint8Array|null);

            /** EncryptedEnvelope encryptedHeader */
            encryptedHeader?: (Uint8Array|null);

            /** EncryptedEnvelope headerNonce */
            headerNonce?: (Uint8Array|null);

            /** EncryptedEnvelope headerTag */
            headerTag?: (Uint8Array|null);

            /** EncryptedEnvelope headerSizeClass */
            headerSizeClass?: (number|null);

            /** EncryptedEnvelope encryptedBody */
            encryptedBody?: (Uint8Array|null);

            /** EncryptedEnvelope bodyNonce */
            bodyNonce?: (Uint8Array|null);

            /** EncryptedEnvelope bodyTag */
            bodyTag?: (Uint8Array|null);

            /** EncryptedEnvelope bodySizeClass */
            bodySizeClass?: (number|null);

            /** EncryptedEnvelope bodyContentAddress */
            bodyContentAddress?: (Uint8Array|null);
        }

        /** Represents an EncryptedEnvelope. */
        class EncryptedEnvelope implements IEncryptedEnvelope {

            /**
             * Constructs a new EncryptedEnvelope.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.message.IEncryptedEnvelope);

            /** EncryptedEnvelope version. */
            public version: number;

            /** EncryptedEnvelope messageId. */
            public messageId: Uint8Array;

            /** EncryptedEnvelope recipients. */
            public recipients: dmcn.message.IRecipientRecord[];

            /** EncryptedEnvelope encryptedPayload. */
            public encryptedPayload: Uint8Array;

            /** EncryptedEnvelope payloadNonce. */
            public payloadNonce: Uint8Array;

            /** EncryptedEnvelope payloadTag. */
            public payloadTag: Uint8Array;

            /** EncryptedEnvelope payloadSizeClass. */
            public payloadSizeClass: number;

            /** EncryptedEnvelope createdAt. */
            public createdAt: (number|Long);

            /** EncryptedEnvelope ratchetPubKey. */
            public ratchetPubKey: Uint8Array;

            /** EncryptedEnvelope encryptedHeader. */
            public encryptedHeader: Uint8Array;

            /** EncryptedEnvelope headerNonce. */
            public headerNonce: Uint8Array;

            /** EncryptedEnvelope headerTag. */
            public headerTag: Uint8Array;

            /** EncryptedEnvelope headerSizeClass. */
            public headerSizeClass: number;

            /** EncryptedEnvelope encryptedBody. */
            public encryptedBody: Uint8Array;

            /** EncryptedEnvelope bodyNonce. */
            public bodyNonce: Uint8Array;

            /** EncryptedEnvelope bodyTag. */
            public bodyTag: Uint8Array;

            /** EncryptedEnvelope bodySizeClass. */
            public bodySizeClass: number;

            /** EncryptedEnvelope bodyContentAddress. */
            public bodyContentAddress: Uint8Array;

            /**
             * Creates a new EncryptedEnvelope instance using the specified properties.
             * @param [properties] Properties to set
             * @returns EncryptedEnvelope instance
             */
            public static create(properties?: dmcn.message.IEncryptedEnvelope): dmcn.message.EncryptedEnvelope;

            /**
             * Encodes the specified EncryptedEnvelope message. Does not implicitly {@link dmcn.message.EncryptedEnvelope.verify|verify} messages.
             * @param message EncryptedEnvelope message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.message.IEncryptedEnvelope, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified EncryptedEnvelope message, length delimited. Does not implicitly {@link dmcn.message.EncryptedEnvelope.verify|verify} messages.
             * @param message EncryptedEnvelope message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.message.IEncryptedEnvelope, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an EncryptedEnvelope message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns EncryptedEnvelope
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.message.EncryptedEnvelope;

            /**
             * Decodes an EncryptedEnvelope message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns EncryptedEnvelope
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.message.EncryptedEnvelope;

            /**
             * Verifies an EncryptedEnvelope message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an EncryptedEnvelope message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns EncryptedEnvelope
             */
            public static fromObject(object: { [k: string]: any }): dmcn.message.EncryptedEnvelope;

            /**
             * Creates a plain object from an EncryptedEnvelope message. Also converts values to other types if specified.
             * @param message EncryptedEnvelope
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.message.EncryptedEnvelope, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this EncryptedEnvelope to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for EncryptedEnvelope
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }
    }

    /** Namespace relay. */
    namespace relay {

        /** Properties of a RelayRequest. */
        interface IRelayRequest {

            /** RelayRequest store */
            store?: (dmcn.relay.IStoreRequest|null);

            /** RelayRequest fetchInit */
            fetchInit?: (dmcn.relay.IFetchInit|null);

            /** RelayRequest fetchProof */
            fetchProof?: (dmcn.relay.IFetchProof|null);

            /** RelayRequest ack */
            ack?: (dmcn.relay.IAckRequest|null);

            /** RelayRequest ping */
            ping?: (dmcn.relay.IPingRequest|null);

            /** RelayRequest mailboxOp */
            mailboxOp?: (dmcn.relay.IMailboxOp|null);

            /** RelayRequest storeInit */
            storeInit?: (dmcn.relay.IStoreInit|null);

            /** RelayRequest onionForward */
            onionForward?: (dmcn.relay.IOnionForwardRequest|null);

            /** RelayRequest getIdentity */
            getIdentity?: (dmcn.relay.IGetIdentityRequest|null);

            /** RelayRequest getDar */
            getDar?: (dmcn.relay.IGetDARRequest|null);

            /** RelayRequest getFleetRoster */
            getFleetRoster?: (dmcn.relay.IGetFleetRosterRequest|null);

            /** RelayRequest getRemoval */
            getRemoval?: (dmcn.relay.IGetRemovalRequest|null);

            /** RelayRequest getBlocklist */
            getBlocklist?: (dmcn.relay.IGetBlocklistRequest|null);

            /** RelayRequest putRecord */
            putRecord?: (dmcn.relay.IPutRecordRequest|null);

            /** RelayRequest getRelayDescriptor */
            getRelayDescriptor?: (dmcn.relay.IGetRelayDescriptorRequest|null);
        }

        /** Represents a RelayRequest. */
        class RelayRequest implements IRelayRequest {

            /**
             * Constructs a new RelayRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IRelayRequest);

            /** RelayRequest store. */
            public store?: (dmcn.relay.IStoreRequest|null);

            /** RelayRequest fetchInit. */
            public fetchInit?: (dmcn.relay.IFetchInit|null);

            /** RelayRequest fetchProof. */
            public fetchProof?: (dmcn.relay.IFetchProof|null);

            /** RelayRequest ack. */
            public ack?: (dmcn.relay.IAckRequest|null);

            /** RelayRequest ping. */
            public ping?: (dmcn.relay.IPingRequest|null);

            /** RelayRequest mailboxOp. */
            public mailboxOp?: (dmcn.relay.IMailboxOp|null);

            /** RelayRequest storeInit. */
            public storeInit?: (dmcn.relay.IStoreInit|null);

            /** RelayRequest onionForward. */
            public onionForward?: (dmcn.relay.IOnionForwardRequest|null);

            /** RelayRequest getIdentity. */
            public getIdentity?: (dmcn.relay.IGetIdentityRequest|null);

            /** RelayRequest getDar. */
            public getDar?: (dmcn.relay.IGetDARRequest|null);

            /** RelayRequest getFleetRoster. */
            public getFleetRoster?: (dmcn.relay.IGetFleetRosterRequest|null);

            /** RelayRequest getRemoval. */
            public getRemoval?: (dmcn.relay.IGetRemovalRequest|null);

            /** RelayRequest getBlocklist. */
            public getBlocklist?: (dmcn.relay.IGetBlocklistRequest|null);

            /** RelayRequest putRecord. */
            public putRecord?: (dmcn.relay.IPutRecordRequest|null);

            /** RelayRequest getRelayDescriptor. */
            public getRelayDescriptor?: (dmcn.relay.IGetRelayDescriptorRequest|null);

            /** RelayRequest request. */
            public request?: ("store"|"fetchInit"|"fetchProof"|"ack"|"ping"|"mailboxOp"|"storeInit"|"onionForward"|"getIdentity"|"getDar"|"getFleetRoster"|"getRemoval"|"getBlocklist"|"putRecord"|"getRelayDescriptor");

            /**
             * Creates a new RelayRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns RelayRequest instance
             */
            public static create(properties?: dmcn.relay.IRelayRequest): dmcn.relay.RelayRequest;

            /**
             * Encodes the specified RelayRequest message. Does not implicitly {@link dmcn.relay.RelayRequest.verify|verify} messages.
             * @param message RelayRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IRelayRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified RelayRequest message, length delimited. Does not implicitly {@link dmcn.relay.RelayRequest.verify|verify} messages.
             * @param message RelayRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IRelayRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a RelayRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns RelayRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.RelayRequest;

            /**
             * Decodes a RelayRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns RelayRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.RelayRequest;

            /**
             * Verifies a RelayRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a RelayRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns RelayRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.RelayRequest;

            /**
             * Creates a plain object from a RelayRequest message. Also converts values to other types if specified.
             * @param message RelayRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.RelayRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this RelayRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for RelayRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a RelayResponse. */
        interface IRelayResponse {

            /** RelayResponse store */
            store?: (dmcn.relay.IStoreResponse|null);

            /** RelayResponse fetchChallenge */
            fetchChallenge?: (dmcn.relay.IFetchChallenge|null);

            /** RelayResponse fetch */
            fetch?: (dmcn.relay.IFetchResponse|null);

            /** RelayResponse ack */
            ack?: (dmcn.relay.IAckResponse|null);

            /** RelayResponse ping */
            ping?: (dmcn.relay.IPingResponse|null);

            /** RelayResponse error */
            error?: (dmcn.relay.IErrorResponse|null);

            /** RelayResponse mailboxList */
            mailboxList?: (dmcn.relay.IMailboxListResponse|null);

            /** RelayResponse mailboxBodyHeader */
            mailboxBodyHeader?: (dmcn.relay.IMailboxBodyHeader|null);

            /** RelayResponse mailboxDelete */
            mailboxDelete?: (dmcn.relay.IMailboxDeleteResponse|null);

            /** RelayResponse onionForward */
            onionForward?: (dmcn.relay.IOnionForwardResponse|null);

            /** RelayResponse getIdentity */
            getIdentity?: (dmcn.relay.IGetIdentityResponse|null);

            /** RelayResponse getDar */
            getDar?: (dmcn.relay.IGetDARResponse|null);

            /** RelayResponse getFleetRoster */
            getFleetRoster?: (dmcn.relay.IGetFleetRosterResponse|null);

            /** RelayResponse getRemoval */
            getRemoval?: (dmcn.relay.IGetRemovalResponse|null);

            /** RelayResponse getBlocklist */
            getBlocklist?: (dmcn.relay.IGetBlocklistResponse|null);

            /** RelayResponse putRecord */
            putRecord?: (dmcn.relay.IPutRecordResponse|null);

            /** RelayResponse getRelayDescriptor */
            getRelayDescriptor?: (dmcn.relay.IGetRelayDescriptorResponse|null);

            /** RelayResponse mailboxKvPut */
            mailboxKvPut?: (dmcn.relay.IMailboxKvPutResponse|null);

            /** RelayResponse mailboxKvGet */
            mailboxKvGet?: (dmcn.relay.IMailboxKvGetResponse|null);

            /** RelayResponse mailboxKvList */
            mailboxKvList?: (dmcn.relay.IMailboxKvListResponse|null);

            /** RelayResponse mailboxKvDelete */
            mailboxKvDelete?: (dmcn.relay.IMailboxKvDeleteResponse|null);

            /** RelayResponse mailboxKvStat */
            mailboxKvStat?: (dmcn.relay.IMailboxKvStatResponse|null);
        }

        /** Represents a RelayResponse. */
        class RelayResponse implements IRelayResponse {

            /**
             * Constructs a new RelayResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IRelayResponse);

            /** RelayResponse store. */
            public store?: (dmcn.relay.IStoreResponse|null);

            /** RelayResponse fetchChallenge. */
            public fetchChallenge?: (dmcn.relay.IFetchChallenge|null);

            /** RelayResponse fetch. */
            public fetch?: (dmcn.relay.IFetchResponse|null);

            /** RelayResponse ack. */
            public ack?: (dmcn.relay.IAckResponse|null);

            /** RelayResponse ping. */
            public ping?: (dmcn.relay.IPingResponse|null);

            /** RelayResponse error. */
            public error?: (dmcn.relay.IErrorResponse|null);

            /** RelayResponse mailboxList. */
            public mailboxList?: (dmcn.relay.IMailboxListResponse|null);

            /** RelayResponse mailboxBodyHeader. */
            public mailboxBodyHeader?: (dmcn.relay.IMailboxBodyHeader|null);

            /** RelayResponse mailboxDelete. */
            public mailboxDelete?: (dmcn.relay.IMailboxDeleteResponse|null);

            /** RelayResponse onionForward. */
            public onionForward?: (dmcn.relay.IOnionForwardResponse|null);

            /** RelayResponse getIdentity. */
            public getIdentity?: (dmcn.relay.IGetIdentityResponse|null);

            /** RelayResponse getDar. */
            public getDar?: (dmcn.relay.IGetDARResponse|null);

            /** RelayResponse getFleetRoster. */
            public getFleetRoster?: (dmcn.relay.IGetFleetRosterResponse|null);

            /** RelayResponse getRemoval. */
            public getRemoval?: (dmcn.relay.IGetRemovalResponse|null);

            /** RelayResponse getBlocklist. */
            public getBlocklist?: (dmcn.relay.IGetBlocklistResponse|null);

            /** RelayResponse putRecord. */
            public putRecord?: (dmcn.relay.IPutRecordResponse|null);

            /** RelayResponse getRelayDescriptor. */
            public getRelayDescriptor?: (dmcn.relay.IGetRelayDescriptorResponse|null);

            /** RelayResponse mailboxKvPut. */
            public mailboxKvPut?: (dmcn.relay.IMailboxKvPutResponse|null);

            /** RelayResponse mailboxKvGet. */
            public mailboxKvGet?: (dmcn.relay.IMailboxKvGetResponse|null);

            /** RelayResponse mailboxKvList. */
            public mailboxKvList?: (dmcn.relay.IMailboxKvListResponse|null);

            /** RelayResponse mailboxKvDelete. */
            public mailboxKvDelete?: (dmcn.relay.IMailboxKvDeleteResponse|null);

            /** RelayResponse mailboxKvStat. */
            public mailboxKvStat?: (dmcn.relay.IMailboxKvStatResponse|null);

            /** RelayResponse response. */
            public response?: ("store"|"fetchChallenge"|"fetch"|"ack"|"ping"|"error"|"mailboxList"|"mailboxBodyHeader"|"mailboxDelete"|"onionForward"|"getIdentity"|"getDar"|"getFleetRoster"|"getRemoval"|"getBlocklist"|"putRecord"|"getRelayDescriptor"|"mailboxKvPut"|"mailboxKvGet"|"mailboxKvList"|"mailboxKvDelete"|"mailboxKvStat");

            /**
             * Creates a new RelayResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns RelayResponse instance
             */
            public static create(properties?: dmcn.relay.IRelayResponse): dmcn.relay.RelayResponse;

            /**
             * Encodes the specified RelayResponse message. Does not implicitly {@link dmcn.relay.RelayResponse.verify|verify} messages.
             * @param message RelayResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IRelayResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified RelayResponse message, length delimited. Does not implicitly {@link dmcn.relay.RelayResponse.verify|verify} messages.
             * @param message RelayResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IRelayResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a RelayResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns RelayResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.RelayResponse;

            /**
             * Decodes a RelayResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns RelayResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.RelayResponse;

            /**
             * Verifies a RelayResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a RelayResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns RelayResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.RelayResponse;

            /**
             * Creates a plain object from a RelayResponse message. Also converts values to other types if specified.
             * @param message RelayResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.RelayResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this RelayResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for RelayResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an OnionPacket. */
        interface IOnionPacket {

            /** OnionPacket version */
            version?: (number|null);

            /** OnionPacket ephemeralPub */
            ephemeralPub?: (Uint8Array|null);

            /** OnionPacket nonce */
            nonce?: (Uint8Array|null);

            /** OnionPacket tag */
            tag?: (Uint8Array|null);

            /** OnionPacket encryptedLayer */
            encryptedLayer?: (Uint8Array|null);
        }

        /** Represents an OnionPacket. */
        class OnionPacket implements IOnionPacket {

            /**
             * Constructs a new OnionPacket.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IOnionPacket);

            /** OnionPacket version. */
            public version: number;

            /** OnionPacket ephemeralPub. */
            public ephemeralPub: Uint8Array;

            /** OnionPacket nonce. */
            public nonce: Uint8Array;

            /** OnionPacket tag. */
            public tag: Uint8Array;

            /** OnionPacket encryptedLayer. */
            public encryptedLayer: Uint8Array;

            /**
             * Creates a new OnionPacket instance using the specified properties.
             * @param [properties] Properties to set
             * @returns OnionPacket instance
             */
            public static create(properties?: dmcn.relay.IOnionPacket): dmcn.relay.OnionPacket;

            /**
             * Encodes the specified OnionPacket message. Does not implicitly {@link dmcn.relay.OnionPacket.verify|verify} messages.
             * @param message OnionPacket message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IOnionPacket, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified OnionPacket message, length delimited. Does not implicitly {@link dmcn.relay.OnionPacket.verify|verify} messages.
             * @param message OnionPacket message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IOnionPacket, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an OnionPacket message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns OnionPacket
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.OnionPacket;

            /**
             * Decodes an OnionPacket message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns OnionPacket
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.OnionPacket;

            /**
             * Verifies an OnionPacket message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an OnionPacket message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns OnionPacket
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.OnionPacket;

            /**
             * Creates a plain object from an OnionPacket message. Also converts values to other types if specified.
             * @param message OnionPacket
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.OnionPacket, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this OnionPacket to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for OnionPacket
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an OnionLayer. */
        interface IOnionLayer {

            /** OnionLayer nextHop */
            nextHop?: (string|null);

            /** OnionLayer ttlUnix */
            ttlUnix?: (number|Long|null);

            /** OnionLayer inner */
            inner?: (dmcn.relay.IOnionPacket|null);

            /** OnionLayer delivery */
            delivery?: (Uint8Array|null);
        }

        /** Represents an OnionLayer. */
        class OnionLayer implements IOnionLayer {

            /**
             * Constructs a new OnionLayer.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IOnionLayer);

            /** OnionLayer nextHop. */
            public nextHop: string;

            /** OnionLayer ttlUnix. */
            public ttlUnix: (number|Long);

            /** OnionLayer inner. */
            public inner?: (dmcn.relay.IOnionPacket|null);

            /** OnionLayer delivery. */
            public delivery: Uint8Array;

            /**
             * Creates a new OnionLayer instance using the specified properties.
             * @param [properties] Properties to set
             * @returns OnionLayer instance
             */
            public static create(properties?: dmcn.relay.IOnionLayer): dmcn.relay.OnionLayer;

            /**
             * Encodes the specified OnionLayer message. Does not implicitly {@link dmcn.relay.OnionLayer.verify|verify} messages.
             * @param message OnionLayer message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IOnionLayer, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified OnionLayer message, length delimited. Does not implicitly {@link dmcn.relay.OnionLayer.verify|verify} messages.
             * @param message OnionLayer message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IOnionLayer, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an OnionLayer message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns OnionLayer
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.OnionLayer;

            /**
             * Decodes an OnionLayer message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns OnionLayer
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.OnionLayer;

            /**
             * Verifies an OnionLayer message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an OnionLayer message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns OnionLayer
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.OnionLayer;

            /**
             * Creates a plain object from an OnionLayer message. Also converts values to other types if specified.
             * @param message OnionLayer
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.OnionLayer, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this OnionLayer to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for OnionLayer
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an OnionForwardRequest. */
        interface IOnionForwardRequest {

            /** OnionForwardRequest packet */
            packet?: (dmcn.relay.IOnionPacket|null);
        }

        /** Represents an OnionForwardRequest. */
        class OnionForwardRequest implements IOnionForwardRequest {

            /**
             * Constructs a new OnionForwardRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IOnionForwardRequest);

            /** OnionForwardRequest packet. */
            public packet?: (dmcn.relay.IOnionPacket|null);

            /**
             * Creates a new OnionForwardRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns OnionForwardRequest instance
             */
            public static create(properties?: dmcn.relay.IOnionForwardRequest): dmcn.relay.OnionForwardRequest;

            /**
             * Encodes the specified OnionForwardRequest message. Does not implicitly {@link dmcn.relay.OnionForwardRequest.verify|verify} messages.
             * @param message OnionForwardRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IOnionForwardRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified OnionForwardRequest message, length delimited. Does not implicitly {@link dmcn.relay.OnionForwardRequest.verify|verify} messages.
             * @param message OnionForwardRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IOnionForwardRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an OnionForwardRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns OnionForwardRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.OnionForwardRequest;

            /**
             * Decodes an OnionForwardRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns OnionForwardRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.OnionForwardRequest;

            /**
             * Verifies an OnionForwardRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an OnionForwardRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns OnionForwardRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.OnionForwardRequest;

            /**
             * Creates a plain object from an OnionForwardRequest message. Also converts values to other types if specified.
             * @param message OnionForwardRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.OnionForwardRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this OnionForwardRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for OnionForwardRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an OnionForwardResponse. */
        interface IOnionForwardResponse {

            /** OnionForwardResponse accepted */
            accepted?: (boolean|null);
        }

        /** Represents an OnionForwardResponse. */
        class OnionForwardResponse implements IOnionForwardResponse {

            /**
             * Constructs a new OnionForwardResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IOnionForwardResponse);

            /** OnionForwardResponse accepted. */
            public accepted: boolean;

            /**
             * Creates a new OnionForwardResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns OnionForwardResponse instance
             */
            public static create(properties?: dmcn.relay.IOnionForwardResponse): dmcn.relay.OnionForwardResponse;

            /**
             * Encodes the specified OnionForwardResponse message. Does not implicitly {@link dmcn.relay.OnionForwardResponse.verify|verify} messages.
             * @param message OnionForwardResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IOnionForwardResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified OnionForwardResponse message, length delimited. Does not implicitly {@link dmcn.relay.OnionForwardResponse.verify|verify} messages.
             * @param message OnionForwardResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IOnionForwardResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an OnionForwardResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns OnionForwardResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.OnionForwardResponse;

            /**
             * Decodes an OnionForwardResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns OnionForwardResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.OnionForwardResponse;

            /**
             * Verifies an OnionForwardResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an OnionForwardResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns OnionForwardResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.OnionForwardResponse;

            /**
             * Creates a plain object from an OnionForwardResponse message. Also converts values to other types if specified.
             * @param message OnionForwardResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.OnionForwardResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this OnionForwardResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for OnionForwardResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a StoreRequest. */
        interface IStoreRequest {

            /** StoreRequest senderAddress */
            senderAddress?: (string|null);

            /** StoreRequest senderSignature */
            senderSignature?: (Uint8Array|null);

            /** StoreRequest envelope */
            envelope?: (dmcn.message.IEncryptedEnvelope|null);
        }

        /** Represents a StoreRequest. */
        class StoreRequest implements IStoreRequest {

            /**
             * Constructs a new StoreRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IStoreRequest);

            /** StoreRequest senderAddress. */
            public senderAddress: string;

            /** StoreRequest senderSignature. */
            public senderSignature: Uint8Array;

            /** StoreRequest envelope. */
            public envelope?: (dmcn.message.IEncryptedEnvelope|null);

            /**
             * Creates a new StoreRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns StoreRequest instance
             */
            public static create(properties?: dmcn.relay.IStoreRequest): dmcn.relay.StoreRequest;

            /**
             * Encodes the specified StoreRequest message. Does not implicitly {@link dmcn.relay.StoreRequest.verify|verify} messages.
             * @param message StoreRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IStoreRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified StoreRequest message, length delimited. Does not implicitly {@link dmcn.relay.StoreRequest.verify|verify} messages.
             * @param message StoreRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IStoreRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a StoreRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns StoreRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.StoreRequest;

            /**
             * Decodes a StoreRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns StoreRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.StoreRequest;

            /**
             * Verifies a StoreRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a StoreRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns StoreRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.StoreRequest;

            /**
             * Creates a plain object from a StoreRequest message. Also converts values to other types if specified.
             * @param message StoreRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.StoreRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this StoreRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for StoreRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a StoreResponse. */
        interface IStoreResponse {

            /** StoreResponse envelopeHash */
            envelopeHash?: (Uint8Array|null);
        }

        /** Represents a StoreResponse. */
        class StoreResponse implements IStoreResponse {

            /**
             * Constructs a new StoreResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IStoreResponse);

            /** StoreResponse envelopeHash. */
            public envelopeHash: Uint8Array;

            /**
             * Creates a new StoreResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns StoreResponse instance
             */
            public static create(properties?: dmcn.relay.IStoreResponse): dmcn.relay.StoreResponse;

            /**
             * Encodes the specified StoreResponse message. Does not implicitly {@link dmcn.relay.StoreResponse.verify|verify} messages.
             * @param message StoreResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IStoreResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified StoreResponse message, length delimited. Does not implicitly {@link dmcn.relay.StoreResponse.verify|verify} messages.
             * @param message StoreResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IStoreResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a StoreResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns StoreResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.StoreResponse;

            /**
             * Decodes a StoreResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns StoreResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.StoreResponse;

            /**
             * Verifies a StoreResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a StoreResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns StoreResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.StoreResponse;

            /**
             * Creates a plain object from a StoreResponse message. Also converts values to other types if specified.
             * @param message StoreResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.StoreResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this StoreResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for StoreResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FetchInit. */
        interface IFetchInit {

            /** FetchInit address */
            address?: (string|null);
        }

        /** Represents a FetchInit. */
        class FetchInit implements IFetchInit {

            /**
             * Constructs a new FetchInit.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IFetchInit);

            /** FetchInit address. */
            public address: string;

            /**
             * Creates a new FetchInit instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FetchInit instance
             */
            public static create(properties?: dmcn.relay.IFetchInit): dmcn.relay.FetchInit;

            /**
             * Encodes the specified FetchInit message. Does not implicitly {@link dmcn.relay.FetchInit.verify|verify} messages.
             * @param message FetchInit message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IFetchInit, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FetchInit message, length delimited. Does not implicitly {@link dmcn.relay.FetchInit.verify|verify} messages.
             * @param message FetchInit message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IFetchInit, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FetchInit message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FetchInit
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.FetchInit;

            /**
             * Decodes a FetchInit message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FetchInit
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.FetchInit;

            /**
             * Verifies a FetchInit message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FetchInit message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FetchInit
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.FetchInit;

            /**
             * Creates a plain object from a FetchInit message. Also converts values to other types if specified.
             * @param message FetchInit
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.FetchInit, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FetchInit to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FetchInit
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FetchChallenge. */
        interface IFetchChallenge {

            /** FetchChallenge nonce */
            nonce?: (Uint8Array|null);
        }

        /** Represents a FetchChallenge. */
        class FetchChallenge implements IFetchChallenge {

            /**
             * Constructs a new FetchChallenge.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IFetchChallenge);

            /** FetchChallenge nonce. */
            public nonce: Uint8Array;

            /**
             * Creates a new FetchChallenge instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FetchChallenge instance
             */
            public static create(properties?: dmcn.relay.IFetchChallenge): dmcn.relay.FetchChallenge;

            /**
             * Encodes the specified FetchChallenge message. Does not implicitly {@link dmcn.relay.FetchChallenge.verify|verify} messages.
             * @param message FetchChallenge message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IFetchChallenge, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FetchChallenge message, length delimited. Does not implicitly {@link dmcn.relay.FetchChallenge.verify|verify} messages.
             * @param message FetchChallenge message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IFetchChallenge, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FetchChallenge message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FetchChallenge
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.FetchChallenge;

            /**
             * Decodes a FetchChallenge message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FetchChallenge
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.FetchChallenge;

            /**
             * Verifies a FetchChallenge message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FetchChallenge message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FetchChallenge
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.FetchChallenge;

            /**
             * Creates a plain object from a FetchChallenge message. Also converts values to other types if specified.
             * @param message FetchChallenge
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.FetchChallenge, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FetchChallenge to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FetchChallenge
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FetchProof. */
        interface IFetchProof {

            /** FetchProof address */
            address?: (string|null);

            /** FetchProof nonce */
            nonce?: (Uint8Array|null);

            /** FetchProof signature */
            signature?: (Uint8Array|null);
        }

        /** Represents a FetchProof. */
        class FetchProof implements IFetchProof {

            /**
             * Constructs a new FetchProof.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IFetchProof);

            /** FetchProof address. */
            public address: string;

            /** FetchProof nonce. */
            public nonce: Uint8Array;

            /** FetchProof signature. */
            public signature: Uint8Array;

            /**
             * Creates a new FetchProof instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FetchProof instance
             */
            public static create(properties?: dmcn.relay.IFetchProof): dmcn.relay.FetchProof;

            /**
             * Encodes the specified FetchProof message. Does not implicitly {@link dmcn.relay.FetchProof.verify|verify} messages.
             * @param message FetchProof message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IFetchProof, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FetchProof message, length delimited. Does not implicitly {@link dmcn.relay.FetchProof.verify|verify} messages.
             * @param message FetchProof message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IFetchProof, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FetchProof message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FetchProof
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.FetchProof;

            /**
             * Decodes a FetchProof message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FetchProof
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.FetchProof;

            /**
             * Verifies a FetchProof message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FetchProof message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FetchProof
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.FetchProof;

            /**
             * Creates a plain object from a FetchProof message. Also converts values to other types if specified.
             * @param message FetchProof
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.FetchProof, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FetchProof to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FetchProof
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a FetchResponse. */
        interface IFetchResponse {

            /** FetchResponse envelopes */
            envelopes?: (dmcn.message.IEncryptedEnvelope[]|null);

            /** FetchResponse envelopeHashes */
            envelopeHashes?: (Uint8Array[]|null);
        }

        /** Represents a FetchResponse. */
        class FetchResponse implements IFetchResponse {

            /**
             * Constructs a new FetchResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IFetchResponse);

            /** FetchResponse envelopes. */
            public envelopes: dmcn.message.IEncryptedEnvelope[];

            /** FetchResponse envelopeHashes. */
            public envelopeHashes: Uint8Array[];

            /**
             * Creates a new FetchResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns FetchResponse instance
             */
            public static create(properties?: dmcn.relay.IFetchResponse): dmcn.relay.FetchResponse;

            /**
             * Encodes the specified FetchResponse message. Does not implicitly {@link dmcn.relay.FetchResponse.verify|verify} messages.
             * @param message FetchResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IFetchResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified FetchResponse message, length delimited. Does not implicitly {@link dmcn.relay.FetchResponse.verify|verify} messages.
             * @param message FetchResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IFetchResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a FetchResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns FetchResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.FetchResponse;

            /**
             * Decodes a FetchResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns FetchResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.FetchResponse;

            /**
             * Verifies a FetchResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a FetchResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns FetchResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.FetchResponse;

            /**
             * Creates a plain object from a FetchResponse message. Also converts values to other types if specified.
             * @param message FetchResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.FetchResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this FetchResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for FetchResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an AckRequest. */
        interface IAckRequest {

            /** AckRequest envelopeHash */
            envelopeHash?: (Uint8Array|null);
        }

        /** Represents an AckRequest. */
        class AckRequest implements IAckRequest {

            /**
             * Constructs a new AckRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IAckRequest);

            /** AckRequest envelopeHash. */
            public envelopeHash: Uint8Array;

            /**
             * Creates a new AckRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AckRequest instance
             */
            public static create(properties?: dmcn.relay.IAckRequest): dmcn.relay.AckRequest;

            /**
             * Encodes the specified AckRequest message. Does not implicitly {@link dmcn.relay.AckRequest.verify|verify} messages.
             * @param message AckRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IAckRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified AckRequest message, length delimited. Does not implicitly {@link dmcn.relay.AckRequest.verify|verify} messages.
             * @param message AckRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IAckRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AckRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns AckRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.AckRequest;

            /**
             * Decodes an AckRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns AckRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.AckRequest;

            /**
             * Verifies an AckRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an AckRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns AckRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.AckRequest;

            /**
             * Creates a plain object from an AckRequest message. Also converts values to other types if specified.
             * @param message AckRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.AckRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this AckRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for AckRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an AckResponse. */
        interface IAckResponse {

            /** AckResponse success */
            success?: (boolean|null);
        }

        /** Represents an AckResponse. */
        class AckResponse implements IAckResponse {

            /**
             * Constructs a new AckResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IAckResponse);

            /** AckResponse success. */
            public success: boolean;

            /**
             * Creates a new AckResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns AckResponse instance
             */
            public static create(properties?: dmcn.relay.IAckResponse): dmcn.relay.AckResponse;

            /**
             * Encodes the specified AckResponse message. Does not implicitly {@link dmcn.relay.AckResponse.verify|verify} messages.
             * @param message AckResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IAckResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified AckResponse message, length delimited. Does not implicitly {@link dmcn.relay.AckResponse.verify|verify} messages.
             * @param message AckResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IAckResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an AckResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns AckResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.AckResponse;

            /**
             * Decodes an AckResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns AckResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.AckResponse;

            /**
             * Verifies an AckResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an AckResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns AckResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.AckResponse;

            /**
             * Creates a plain object from an AckResponse message. Also converts values to other types if specified.
             * @param message AckResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.AckResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this AckResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for AckResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a PingRequest. */
        interface IPingRequest {
        }

        /** Represents a PingRequest. */
        class PingRequest implements IPingRequest {

            /**
             * Constructs a new PingRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IPingRequest);

            /**
             * Creates a new PingRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PingRequest instance
             */
            public static create(properties?: dmcn.relay.IPingRequest): dmcn.relay.PingRequest;

            /**
             * Encodes the specified PingRequest message. Does not implicitly {@link dmcn.relay.PingRequest.verify|verify} messages.
             * @param message PingRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IPingRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PingRequest message, length delimited. Does not implicitly {@link dmcn.relay.PingRequest.verify|verify} messages.
             * @param message PingRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IPingRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PingRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PingRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.PingRequest;

            /**
             * Decodes a PingRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PingRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.PingRequest;

            /**
             * Verifies a PingRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PingRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PingRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.PingRequest;

            /**
             * Creates a plain object from a PingRequest message. Also converts values to other types if specified.
             * @param message PingRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.PingRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PingRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PingRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a PingResponse. */
        interface IPingResponse {

            /** PingResponse version */
            version?: (string|null);

            /** PingResponse uptimeSeconds */
            uptimeSeconds?: (number|Long|null);

            /** PingResponse storedEnvelopes */
            storedEnvelopes?: (number|null);
        }

        /** Represents a PingResponse. */
        class PingResponse implements IPingResponse {

            /**
             * Constructs a new PingResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IPingResponse);

            /** PingResponse version. */
            public version: string;

            /** PingResponse uptimeSeconds. */
            public uptimeSeconds: (number|Long);

            /** PingResponse storedEnvelopes. */
            public storedEnvelopes: number;

            /**
             * Creates a new PingResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PingResponse instance
             */
            public static create(properties?: dmcn.relay.IPingResponse): dmcn.relay.PingResponse;

            /**
             * Encodes the specified PingResponse message. Does not implicitly {@link dmcn.relay.PingResponse.verify|verify} messages.
             * @param message PingResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IPingResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PingResponse message, length delimited. Does not implicitly {@link dmcn.relay.PingResponse.verify|verify} messages.
             * @param message PingResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IPingResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PingResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PingResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.PingResponse;

            /**
             * Decodes a PingResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PingResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.PingResponse;

            /**
             * Verifies a PingResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PingResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PingResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.PingResponse;

            /**
             * Creates a plain object from a PingResponse message. Also converts values to other types if specified.
             * @param message PingResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.PingResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PingResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PingResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetIdentityRequest. */
        interface IGetIdentityRequest {

            /** GetIdentityRequest address */
            address?: (string|null);
        }

        /** Represents a GetIdentityRequest. */
        class GetIdentityRequest implements IGetIdentityRequest {

            /**
             * Constructs a new GetIdentityRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetIdentityRequest);

            /** GetIdentityRequest address. */
            public address: string;

            /**
             * Creates a new GetIdentityRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetIdentityRequest instance
             */
            public static create(properties?: dmcn.relay.IGetIdentityRequest): dmcn.relay.GetIdentityRequest;

            /**
             * Encodes the specified GetIdentityRequest message. Does not implicitly {@link dmcn.relay.GetIdentityRequest.verify|verify} messages.
             * @param message GetIdentityRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetIdentityRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetIdentityRequest message, length delimited. Does not implicitly {@link dmcn.relay.GetIdentityRequest.verify|verify} messages.
             * @param message GetIdentityRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetIdentityRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetIdentityRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetIdentityRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetIdentityRequest;

            /**
             * Decodes a GetIdentityRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetIdentityRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetIdentityRequest;

            /**
             * Verifies a GetIdentityRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetIdentityRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetIdentityRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetIdentityRequest;

            /**
             * Creates a plain object from a GetIdentityRequest message. Also converts values to other types if specified.
             * @param message GetIdentityRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetIdentityRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetIdentityRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetIdentityRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetIdentityResponse. */
        interface IGetIdentityResponse {

            /** GetIdentityResponse found */
            found?: (boolean|null);

            /** GetIdentityResponse record */
            record?: (Uint8Array|null);
        }

        /** Represents a GetIdentityResponse. */
        class GetIdentityResponse implements IGetIdentityResponse {

            /**
             * Constructs a new GetIdentityResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetIdentityResponse);

            /** GetIdentityResponse found. */
            public found: boolean;

            /** GetIdentityResponse record. */
            public record: Uint8Array;

            /**
             * Creates a new GetIdentityResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetIdentityResponse instance
             */
            public static create(properties?: dmcn.relay.IGetIdentityResponse): dmcn.relay.GetIdentityResponse;

            /**
             * Encodes the specified GetIdentityResponse message. Does not implicitly {@link dmcn.relay.GetIdentityResponse.verify|verify} messages.
             * @param message GetIdentityResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetIdentityResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetIdentityResponse message, length delimited. Does not implicitly {@link dmcn.relay.GetIdentityResponse.verify|verify} messages.
             * @param message GetIdentityResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetIdentityResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetIdentityResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetIdentityResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetIdentityResponse;

            /**
             * Decodes a GetIdentityResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetIdentityResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetIdentityResponse;

            /**
             * Verifies a GetIdentityResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetIdentityResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetIdentityResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetIdentityResponse;

            /**
             * Creates a plain object from a GetIdentityResponse message. Also converts values to other types if specified.
             * @param message GetIdentityResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetIdentityResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetIdentityResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetIdentityResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetDARRequest. */
        interface IGetDARRequest {

            /** GetDARRequest domain */
            domain?: (string|null);
        }

        /** Represents a GetDARRequest. */
        class GetDARRequest implements IGetDARRequest {

            /**
             * Constructs a new GetDARRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetDARRequest);

            /** GetDARRequest domain. */
            public domain: string;

            /**
             * Creates a new GetDARRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetDARRequest instance
             */
            public static create(properties?: dmcn.relay.IGetDARRequest): dmcn.relay.GetDARRequest;

            /**
             * Encodes the specified GetDARRequest message. Does not implicitly {@link dmcn.relay.GetDARRequest.verify|verify} messages.
             * @param message GetDARRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetDARRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetDARRequest message, length delimited. Does not implicitly {@link dmcn.relay.GetDARRequest.verify|verify} messages.
             * @param message GetDARRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetDARRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetDARRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetDARRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetDARRequest;

            /**
             * Decodes a GetDARRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetDARRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetDARRequest;

            /**
             * Verifies a GetDARRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetDARRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetDARRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetDARRequest;

            /**
             * Creates a plain object from a GetDARRequest message. Also converts values to other types if specified.
             * @param message GetDARRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetDARRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetDARRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetDARRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetDARResponse. */
        interface IGetDARResponse {

            /** GetDARResponse found */
            found?: (boolean|null);

            /** GetDARResponse record */
            record?: (Uint8Array|null);
        }

        /** Represents a GetDARResponse. */
        class GetDARResponse implements IGetDARResponse {

            /**
             * Constructs a new GetDARResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetDARResponse);

            /** GetDARResponse found. */
            public found: boolean;

            /** GetDARResponse record. */
            public record: Uint8Array;

            /**
             * Creates a new GetDARResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetDARResponse instance
             */
            public static create(properties?: dmcn.relay.IGetDARResponse): dmcn.relay.GetDARResponse;

            /**
             * Encodes the specified GetDARResponse message. Does not implicitly {@link dmcn.relay.GetDARResponse.verify|verify} messages.
             * @param message GetDARResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetDARResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetDARResponse message, length delimited. Does not implicitly {@link dmcn.relay.GetDARResponse.verify|verify} messages.
             * @param message GetDARResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetDARResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetDARResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetDARResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetDARResponse;

            /**
             * Decodes a GetDARResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetDARResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetDARResponse;

            /**
             * Verifies a GetDARResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetDARResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetDARResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetDARResponse;

            /**
             * Creates a plain object from a GetDARResponse message. Also converts values to other types if specified.
             * @param message GetDARResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetDARResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetDARResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetDARResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetFleetRosterRequest. */
        interface IGetFleetRosterRequest {

            /** GetFleetRosterRequest fleetDomain */
            fleetDomain?: (string|null);
        }

        /** Represents a GetFleetRosterRequest. */
        class GetFleetRosterRequest implements IGetFleetRosterRequest {

            /**
             * Constructs a new GetFleetRosterRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetFleetRosterRequest);

            /** GetFleetRosterRequest fleetDomain. */
            public fleetDomain: string;

            /**
             * Creates a new GetFleetRosterRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetFleetRosterRequest instance
             */
            public static create(properties?: dmcn.relay.IGetFleetRosterRequest): dmcn.relay.GetFleetRosterRequest;

            /**
             * Encodes the specified GetFleetRosterRequest message. Does not implicitly {@link dmcn.relay.GetFleetRosterRequest.verify|verify} messages.
             * @param message GetFleetRosterRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetFleetRosterRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetFleetRosterRequest message, length delimited. Does not implicitly {@link dmcn.relay.GetFleetRosterRequest.verify|verify} messages.
             * @param message GetFleetRosterRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetFleetRosterRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetFleetRosterRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetFleetRosterRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetFleetRosterRequest;

            /**
             * Decodes a GetFleetRosterRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetFleetRosterRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetFleetRosterRequest;

            /**
             * Verifies a GetFleetRosterRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetFleetRosterRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetFleetRosterRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetFleetRosterRequest;

            /**
             * Creates a plain object from a GetFleetRosterRequest message. Also converts values to other types if specified.
             * @param message GetFleetRosterRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetFleetRosterRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetFleetRosterRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetFleetRosterRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetFleetRosterResponse. */
        interface IGetFleetRosterResponse {

            /** GetFleetRosterResponse found */
            found?: (boolean|null);

            /** GetFleetRosterResponse record */
            record?: (Uint8Array|null);
        }

        /** Represents a GetFleetRosterResponse. */
        class GetFleetRosterResponse implements IGetFleetRosterResponse {

            /**
             * Constructs a new GetFleetRosterResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetFleetRosterResponse);

            /** GetFleetRosterResponse found. */
            public found: boolean;

            /** GetFleetRosterResponse record. */
            public record: Uint8Array;

            /**
             * Creates a new GetFleetRosterResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetFleetRosterResponse instance
             */
            public static create(properties?: dmcn.relay.IGetFleetRosterResponse): dmcn.relay.GetFleetRosterResponse;

            /**
             * Encodes the specified GetFleetRosterResponse message. Does not implicitly {@link dmcn.relay.GetFleetRosterResponse.verify|verify} messages.
             * @param message GetFleetRosterResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetFleetRosterResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetFleetRosterResponse message, length delimited. Does not implicitly {@link dmcn.relay.GetFleetRosterResponse.verify|verify} messages.
             * @param message GetFleetRosterResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetFleetRosterResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetFleetRosterResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetFleetRosterResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetFleetRosterResponse;

            /**
             * Decodes a GetFleetRosterResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetFleetRosterResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetFleetRosterResponse;

            /**
             * Verifies a GetFleetRosterResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetFleetRosterResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetFleetRosterResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetFleetRosterResponse;

            /**
             * Creates a plain object from a GetFleetRosterResponse message. Also converts values to other types if specified.
             * @param message GetFleetRosterResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetFleetRosterResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetFleetRosterResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetFleetRosterResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetRemovalRequest. */
        interface IGetRemovalRequest {

            /** GetRemovalRequest address */
            address?: (string|null);
        }

        /** Represents a GetRemovalRequest. */
        class GetRemovalRequest implements IGetRemovalRequest {

            /**
             * Constructs a new GetRemovalRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetRemovalRequest);

            /** GetRemovalRequest address. */
            public address: string;

            /**
             * Creates a new GetRemovalRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetRemovalRequest instance
             */
            public static create(properties?: dmcn.relay.IGetRemovalRequest): dmcn.relay.GetRemovalRequest;

            /**
             * Encodes the specified GetRemovalRequest message. Does not implicitly {@link dmcn.relay.GetRemovalRequest.verify|verify} messages.
             * @param message GetRemovalRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetRemovalRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetRemovalRequest message, length delimited. Does not implicitly {@link dmcn.relay.GetRemovalRequest.verify|verify} messages.
             * @param message GetRemovalRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetRemovalRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetRemovalRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetRemovalRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetRemovalRequest;

            /**
             * Decodes a GetRemovalRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetRemovalRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetRemovalRequest;

            /**
             * Verifies a GetRemovalRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetRemovalRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetRemovalRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetRemovalRequest;

            /**
             * Creates a plain object from a GetRemovalRequest message. Also converts values to other types if specified.
             * @param message GetRemovalRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetRemovalRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetRemovalRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetRemovalRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetRemovalResponse. */
        interface IGetRemovalResponse {

            /** GetRemovalResponse found */
            found?: (boolean|null);

            /** GetRemovalResponse record */
            record?: (Uint8Array|null);
        }

        /** Represents a GetRemovalResponse. */
        class GetRemovalResponse implements IGetRemovalResponse {

            /**
             * Constructs a new GetRemovalResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetRemovalResponse);

            /** GetRemovalResponse found. */
            public found: boolean;

            /** GetRemovalResponse record. */
            public record: Uint8Array;

            /**
             * Creates a new GetRemovalResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetRemovalResponse instance
             */
            public static create(properties?: dmcn.relay.IGetRemovalResponse): dmcn.relay.GetRemovalResponse;

            /**
             * Encodes the specified GetRemovalResponse message. Does not implicitly {@link dmcn.relay.GetRemovalResponse.verify|verify} messages.
             * @param message GetRemovalResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetRemovalResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetRemovalResponse message, length delimited. Does not implicitly {@link dmcn.relay.GetRemovalResponse.verify|verify} messages.
             * @param message GetRemovalResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetRemovalResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetRemovalResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetRemovalResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetRemovalResponse;

            /**
             * Decodes a GetRemovalResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetRemovalResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetRemovalResponse;

            /**
             * Verifies a GetRemovalResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetRemovalResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetRemovalResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetRemovalResponse;

            /**
             * Creates a plain object from a GetRemovalResponse message. Also converts values to other types if specified.
             * @param message GetRemovalResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetRemovalResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetRemovalResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetRemovalResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetBlocklistRequest. */
        interface IGetBlocklistRequest {

            /** GetBlocklistRequest domain */
            domain?: (string|null);
        }

        /** Represents a GetBlocklistRequest. */
        class GetBlocklistRequest implements IGetBlocklistRequest {

            /**
             * Constructs a new GetBlocklistRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetBlocklistRequest);

            /** GetBlocklistRequest domain. */
            public domain: string;

            /**
             * Creates a new GetBlocklistRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetBlocklistRequest instance
             */
            public static create(properties?: dmcn.relay.IGetBlocklistRequest): dmcn.relay.GetBlocklistRequest;

            /**
             * Encodes the specified GetBlocklistRequest message. Does not implicitly {@link dmcn.relay.GetBlocklistRequest.verify|verify} messages.
             * @param message GetBlocklistRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetBlocklistRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetBlocklistRequest message, length delimited. Does not implicitly {@link dmcn.relay.GetBlocklistRequest.verify|verify} messages.
             * @param message GetBlocklistRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetBlocklistRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetBlocklistRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetBlocklistRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetBlocklistRequest;

            /**
             * Decodes a GetBlocklistRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetBlocklistRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetBlocklistRequest;

            /**
             * Verifies a GetBlocklistRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetBlocklistRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetBlocklistRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetBlocklistRequest;

            /**
             * Creates a plain object from a GetBlocklistRequest message. Also converts values to other types if specified.
             * @param message GetBlocklistRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetBlocklistRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetBlocklistRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetBlocklistRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetBlocklistResponse. */
        interface IGetBlocklistResponse {

            /** GetBlocklistResponse found */
            found?: (boolean|null);

            /** GetBlocklistResponse record */
            record?: (Uint8Array|null);
        }

        /** Represents a GetBlocklistResponse. */
        class GetBlocklistResponse implements IGetBlocklistResponse {

            /**
             * Constructs a new GetBlocklistResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetBlocklistResponse);

            /** GetBlocklistResponse found. */
            public found: boolean;

            /** GetBlocklistResponse record. */
            public record: Uint8Array;

            /**
             * Creates a new GetBlocklistResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetBlocklistResponse instance
             */
            public static create(properties?: dmcn.relay.IGetBlocklistResponse): dmcn.relay.GetBlocklistResponse;

            /**
             * Encodes the specified GetBlocklistResponse message. Does not implicitly {@link dmcn.relay.GetBlocklistResponse.verify|verify} messages.
             * @param message GetBlocklistResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetBlocklistResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetBlocklistResponse message, length delimited. Does not implicitly {@link dmcn.relay.GetBlocklistResponse.verify|verify} messages.
             * @param message GetBlocklistResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetBlocklistResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetBlocklistResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetBlocklistResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetBlocklistResponse;

            /**
             * Decodes a GetBlocklistResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetBlocklistResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetBlocklistResponse;

            /**
             * Verifies a GetBlocklistResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetBlocklistResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetBlocklistResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetBlocklistResponse;

            /**
             * Creates a plain object from a GetBlocklistResponse message. Also converts values to other types if specified.
             * @param message GetBlocklistResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetBlocklistResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetBlocklistResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetBlocklistResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** RecordKind enum. */
        enum RecordKind {
            RECORD_KIND_UNSPECIFIED = 0,
            RECORD_KIND_IDENTITY = 1,
            RECORD_KIND_DAR = 2,
            RECORD_KIND_ROSTER = 3,
            RECORD_KIND_REMOVAL = 4,
            RECORD_KIND_BLOCKLIST = 5
        }

        /** Properties of a PutRecordRequest. */
        interface IPutRecordRequest {

            /** PutRecordRequest kind */
            kind?: (dmcn.relay.RecordKind|null);

            /** PutRecordRequest record */
            record?: (Uint8Array|null);
        }

        /** Represents a PutRecordRequest. */
        class PutRecordRequest implements IPutRecordRequest {

            /**
             * Constructs a new PutRecordRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IPutRecordRequest);

            /** PutRecordRequest kind. */
            public kind: dmcn.relay.RecordKind;

            /** PutRecordRequest record. */
            public record: Uint8Array;

            /**
             * Creates a new PutRecordRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PutRecordRequest instance
             */
            public static create(properties?: dmcn.relay.IPutRecordRequest): dmcn.relay.PutRecordRequest;

            /**
             * Encodes the specified PutRecordRequest message. Does not implicitly {@link dmcn.relay.PutRecordRequest.verify|verify} messages.
             * @param message PutRecordRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IPutRecordRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PutRecordRequest message, length delimited. Does not implicitly {@link dmcn.relay.PutRecordRequest.verify|verify} messages.
             * @param message PutRecordRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IPutRecordRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PutRecordRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PutRecordRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.PutRecordRequest;

            /**
             * Decodes a PutRecordRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PutRecordRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.PutRecordRequest;

            /**
             * Verifies a PutRecordRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PutRecordRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PutRecordRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.PutRecordRequest;

            /**
             * Creates a plain object from a PutRecordRequest message. Also converts values to other types if specified.
             * @param message PutRecordRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.PutRecordRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PutRecordRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PutRecordRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a PutRecordResponse. */
        interface IPutRecordResponse {

            /** PutRecordResponse accepted */
            accepted?: (boolean|null);

            /** PutRecordResponse reason */
            reason?: (string|null);
        }

        /** Represents a PutRecordResponse. */
        class PutRecordResponse implements IPutRecordResponse {

            /**
             * Constructs a new PutRecordResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IPutRecordResponse);

            /** PutRecordResponse accepted. */
            public accepted: boolean;

            /** PutRecordResponse reason. */
            public reason: string;

            /**
             * Creates a new PutRecordResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PutRecordResponse instance
             */
            public static create(properties?: dmcn.relay.IPutRecordResponse): dmcn.relay.PutRecordResponse;

            /**
             * Encodes the specified PutRecordResponse message. Does not implicitly {@link dmcn.relay.PutRecordResponse.verify|verify} messages.
             * @param message PutRecordResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IPutRecordResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PutRecordResponse message, length delimited. Does not implicitly {@link dmcn.relay.PutRecordResponse.verify|verify} messages.
             * @param message PutRecordResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IPutRecordResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PutRecordResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PutRecordResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.PutRecordResponse;

            /**
             * Decodes a PutRecordResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PutRecordResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.PutRecordResponse;

            /**
             * Verifies a PutRecordResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PutRecordResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PutRecordResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.PutRecordResponse;

            /**
             * Creates a plain object from a PutRecordResponse message. Also converts values to other types if specified.
             * @param message PutRecordResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.PutRecordResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PutRecordResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PutRecordResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetRelayDescriptorRequest. */
        interface IGetRelayDescriptorRequest {

            /** GetRelayDescriptorRequest peerId */
            peerId?: (string|null);
        }

        /** Represents a GetRelayDescriptorRequest. */
        class GetRelayDescriptorRequest implements IGetRelayDescriptorRequest {

            /**
             * Constructs a new GetRelayDescriptorRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetRelayDescriptorRequest);

            /** GetRelayDescriptorRequest peerId. */
            public peerId: string;

            /**
             * Creates a new GetRelayDescriptorRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetRelayDescriptorRequest instance
             */
            public static create(properties?: dmcn.relay.IGetRelayDescriptorRequest): dmcn.relay.GetRelayDescriptorRequest;

            /**
             * Encodes the specified GetRelayDescriptorRequest message. Does not implicitly {@link dmcn.relay.GetRelayDescriptorRequest.verify|verify} messages.
             * @param message GetRelayDescriptorRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetRelayDescriptorRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetRelayDescriptorRequest message, length delimited. Does not implicitly {@link dmcn.relay.GetRelayDescriptorRequest.verify|verify} messages.
             * @param message GetRelayDescriptorRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetRelayDescriptorRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetRelayDescriptorRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetRelayDescriptorRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetRelayDescriptorRequest;

            /**
             * Decodes a GetRelayDescriptorRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetRelayDescriptorRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetRelayDescriptorRequest;

            /**
             * Verifies a GetRelayDescriptorRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetRelayDescriptorRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetRelayDescriptorRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetRelayDescriptorRequest;

            /**
             * Creates a plain object from a GetRelayDescriptorRequest message. Also converts values to other types if specified.
             * @param message GetRelayDescriptorRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetRelayDescriptorRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetRelayDescriptorRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetRelayDescriptorRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a GetRelayDescriptorResponse. */
        interface IGetRelayDescriptorResponse {

            /** GetRelayDescriptorResponse found */
            found?: (boolean|null);

            /** GetRelayDescriptorResponse record */
            record?: (Uint8Array|null);
        }

        /** Represents a GetRelayDescriptorResponse. */
        class GetRelayDescriptorResponse implements IGetRelayDescriptorResponse {

            /**
             * Constructs a new GetRelayDescriptorResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IGetRelayDescriptorResponse);

            /** GetRelayDescriptorResponse found. */
            public found: boolean;

            /** GetRelayDescriptorResponse record. */
            public record: Uint8Array;

            /**
             * Creates a new GetRelayDescriptorResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns GetRelayDescriptorResponse instance
             */
            public static create(properties?: dmcn.relay.IGetRelayDescriptorResponse): dmcn.relay.GetRelayDescriptorResponse;

            /**
             * Encodes the specified GetRelayDescriptorResponse message. Does not implicitly {@link dmcn.relay.GetRelayDescriptorResponse.verify|verify} messages.
             * @param message GetRelayDescriptorResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IGetRelayDescriptorResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified GetRelayDescriptorResponse message, length delimited. Does not implicitly {@link dmcn.relay.GetRelayDescriptorResponse.verify|verify} messages.
             * @param message GetRelayDescriptorResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IGetRelayDescriptorResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a GetRelayDescriptorResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns GetRelayDescriptorResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.GetRelayDescriptorResponse;

            /**
             * Decodes a GetRelayDescriptorResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns GetRelayDescriptorResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.GetRelayDescriptorResponse;

            /**
             * Verifies a GetRelayDescriptorResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a GetRelayDescriptorResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns GetRelayDescriptorResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.GetRelayDescriptorResponse;

            /**
             * Creates a plain object from a GetRelayDescriptorResponse message. Also converts values to other types if specified.
             * @param message GetRelayDescriptorResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.GetRelayDescriptorResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this GetRelayDescriptorResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for GetRelayDescriptorResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of an ErrorResponse. */
        interface IErrorResponse {

            /** ErrorResponse code */
            code?: (string|null);

            /** ErrorResponse message */
            message?: (string|null);
        }

        /** Represents an ErrorResponse. */
        class ErrorResponse implements IErrorResponse {

            /**
             * Constructs a new ErrorResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IErrorResponse);

            /** ErrorResponse code. */
            public code: string;

            /** ErrorResponse message. */
            public message: string;

            /**
             * Creates a new ErrorResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns ErrorResponse instance
             */
            public static create(properties?: dmcn.relay.IErrorResponse): dmcn.relay.ErrorResponse;

            /**
             * Encodes the specified ErrorResponse message. Does not implicitly {@link dmcn.relay.ErrorResponse.verify|verify} messages.
             * @param message ErrorResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IErrorResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified ErrorResponse message, length delimited. Does not implicitly {@link dmcn.relay.ErrorResponse.verify|verify} messages.
             * @param message ErrorResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IErrorResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes an ErrorResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns ErrorResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.ErrorResponse;

            /**
             * Decodes an ErrorResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns ErrorResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.ErrorResponse;

            /**
             * Verifies an ErrorResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates an ErrorResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns ErrorResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.ErrorResponse;

            /**
             * Creates a plain object from an ErrorResponse message. Also converts values to other types if specified.
             * @param message ErrorResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.ErrorResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this ErrorResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for ErrorResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a PeersRequest. */
        interface IPeersRequest {
        }

        /** Represents a PeersRequest. */
        class PeersRequest implements IPeersRequest {

            /**
             * Constructs a new PeersRequest.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IPeersRequest);

            /**
             * Creates a new PeersRequest instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PeersRequest instance
             */
            public static create(properties?: dmcn.relay.IPeersRequest): dmcn.relay.PeersRequest;

            /**
             * Encodes the specified PeersRequest message. Does not implicitly {@link dmcn.relay.PeersRequest.verify|verify} messages.
             * @param message PeersRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IPeersRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PeersRequest message, length delimited. Does not implicitly {@link dmcn.relay.PeersRequest.verify|verify} messages.
             * @param message PeersRequest message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IPeersRequest, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PeersRequest message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PeersRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.PeersRequest;

            /**
             * Decodes a PeersRequest message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PeersRequest
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.PeersRequest;

            /**
             * Verifies a PeersRequest message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PeersRequest message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PeersRequest
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.PeersRequest;

            /**
             * Creates a plain object from a PeersRequest message. Also converts values to other types if specified.
             * @param message PeersRequest
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.PeersRequest, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PeersRequest to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PeersRequest
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a PeersResponse. */
        interface IPeersResponse {

            /** PeersResponse peers */
            peers?: (string[]|null);
        }

        /** Represents a PeersResponse. */
        class PeersResponse implements IPeersResponse {

            /**
             * Constructs a new PeersResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IPeersResponse);

            /** PeersResponse peers. */
            public peers: string[];

            /**
             * Creates a new PeersResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns PeersResponse instance
             */
            public static create(properties?: dmcn.relay.IPeersResponse): dmcn.relay.PeersResponse;

            /**
             * Encodes the specified PeersResponse message. Does not implicitly {@link dmcn.relay.PeersResponse.verify|verify} messages.
             * @param message PeersResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IPeersResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified PeersResponse message, length delimited. Does not implicitly {@link dmcn.relay.PeersResponse.verify|verify} messages.
             * @param message PeersResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IPeersResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a PeersResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns PeersResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.PeersResponse;

            /**
             * Decodes a PeersResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns PeersResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.PeersResponse;

            /**
             * Verifies a PeersResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a PeersResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns PeersResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.PeersResponse;

            /**
             * Creates a plain object from a PeersResponse message. Also converts values to other types if specified.
             * @param message PeersResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.PeersResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this PeersResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for PeersResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxEntry. */
        interface IMailboxEntry {

            /** MailboxEntry hash */
            hash?: (Uint8Array|null);

            /** MailboxEntry storedAt */
            storedAt?: (number|Long|null);

            /** MailboxEntry bodySize */
            bodySize?: (number|Long|null);

            /** MailboxEntry recipients */
            recipients?: (dmcn.message.IRecipientRecord[]|null);

            /** MailboxEntry encryptedHeader */
            encryptedHeader?: (Uint8Array|null);

            /** MailboxEntry headerNonce */
            headerNonce?: (Uint8Array|null);

            /** MailboxEntry headerTag */
            headerTag?: (Uint8Array|null);

            /** MailboxEntry headerSizeClass */
            headerSizeClass?: (number|null);

            /** MailboxEntry bodyContentAddress */
            bodyContentAddress?: (Uint8Array|null);
        }

        /** Represents a MailboxEntry. */
        class MailboxEntry implements IMailboxEntry {

            /**
             * Constructs a new MailboxEntry.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxEntry);

            /** MailboxEntry hash. */
            public hash: Uint8Array;

            /** MailboxEntry storedAt. */
            public storedAt: (number|Long);

            /** MailboxEntry bodySize. */
            public bodySize: (number|Long);

            /** MailboxEntry recipients. */
            public recipients: dmcn.message.IRecipientRecord[];

            /** MailboxEntry encryptedHeader. */
            public encryptedHeader: Uint8Array;

            /** MailboxEntry headerNonce. */
            public headerNonce: Uint8Array;

            /** MailboxEntry headerTag. */
            public headerTag: Uint8Array;

            /** MailboxEntry headerSizeClass. */
            public headerSizeClass: number;

            /** MailboxEntry bodyContentAddress. */
            public bodyContentAddress: Uint8Array;

            /**
             * Creates a new MailboxEntry instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxEntry instance
             */
            public static create(properties?: dmcn.relay.IMailboxEntry): dmcn.relay.MailboxEntry;

            /**
             * Encodes the specified MailboxEntry message. Does not implicitly {@link dmcn.relay.MailboxEntry.verify|verify} messages.
             * @param message MailboxEntry message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxEntry, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxEntry message, length delimited. Does not implicitly {@link dmcn.relay.MailboxEntry.verify|verify} messages.
             * @param message MailboxEntry message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxEntry, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxEntry message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxEntry
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxEntry;

            /**
             * Decodes a MailboxEntry message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxEntry
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxEntry;

            /**
             * Verifies a MailboxEntry message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxEntry message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxEntry
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxEntry;

            /**
             * Creates a plain object from a MailboxEntry message. Also converts values to other types if specified.
             * @param message MailboxEntry
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxEntry, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxEntry to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxEntry
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxBody. */
        interface IMailboxBody {

            /** MailboxBody encryptedBody */
            encryptedBody?: (Uint8Array|null);

            /** MailboxBody bodyNonce */
            bodyNonce?: (Uint8Array|null);

            /** MailboxBody bodyTag */
            bodyTag?: (Uint8Array|null);

            /** MailboxBody bodySizeClass */
            bodySizeClass?: (number|null);

            /** MailboxBody bodyContentAddress */
            bodyContentAddress?: (Uint8Array|null);
        }

        /** Represents a MailboxBody. */
        class MailboxBody implements IMailboxBody {

            /**
             * Constructs a new MailboxBody.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxBody);

            /** MailboxBody encryptedBody. */
            public encryptedBody: Uint8Array;

            /** MailboxBody bodyNonce. */
            public bodyNonce: Uint8Array;

            /** MailboxBody bodyTag. */
            public bodyTag: Uint8Array;

            /** MailboxBody bodySizeClass. */
            public bodySizeClass: number;

            /** MailboxBody bodyContentAddress. */
            public bodyContentAddress: Uint8Array;

            /**
             * Creates a new MailboxBody instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxBody instance
             */
            public static create(properties?: dmcn.relay.IMailboxBody): dmcn.relay.MailboxBody;

            /**
             * Encodes the specified MailboxBody message. Does not implicitly {@link dmcn.relay.MailboxBody.verify|verify} messages.
             * @param message MailboxBody message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxBody, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxBody message, length delimited. Does not implicitly {@link dmcn.relay.MailboxBody.verify|verify} messages.
             * @param message MailboxBody message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxBody, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxBody message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxBody
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxBody;

            /**
             * Decodes a MailboxBody message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxBody
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxBody;

            /**
             * Verifies a MailboxBody message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxBody message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxBody
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxBody;

            /**
             * Creates a plain object from a MailboxBody message. Also converts values to other types if specified.
             * @param message MailboxBody
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxBody, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxBody to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxBody
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxOp. */
        interface IMailboxOp {

            /** MailboxOp nonce */
            nonce?: (Uint8Array|null);

            /** MailboxOp signature */
            signature?: (Uint8Array|null);

            /** MailboxOp list */
            list?: (dmcn.relay.IMailboxListOp|null);

            /** MailboxOp body */
            body?: (dmcn.relay.IMailboxBodyOp|null);

            /** MailboxOp delete */
            "delete"?: (dmcn.relay.IMailboxDeleteOp|null);

            /** MailboxOp kvPut */
            kvPut?: (dmcn.relay.IMailboxKvPutOp|null);

            /** MailboxOp kvGet */
            kvGet?: (dmcn.relay.IMailboxKvGetOp|null);

            /** MailboxOp kvList */
            kvList?: (dmcn.relay.IMailboxKvListOp|null);

            /** MailboxOp kvDelete */
            kvDelete?: (dmcn.relay.IMailboxKvDeleteOp|null);

            /** MailboxOp kvStat */
            kvStat?: (dmcn.relay.IMailboxKvStatOp|null);
        }

        /** Represents a MailboxOp. */
        class MailboxOp implements IMailboxOp {

            /**
             * Constructs a new MailboxOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxOp);

            /** MailboxOp nonce. */
            public nonce: Uint8Array;

            /** MailboxOp signature. */
            public signature: Uint8Array;

            /** MailboxOp list. */
            public list?: (dmcn.relay.IMailboxListOp|null);

            /** MailboxOp body. */
            public body?: (dmcn.relay.IMailboxBodyOp|null);

            /** MailboxOp delete. */
            public delete?: (dmcn.relay.IMailboxDeleteOp|null);

            /** MailboxOp kvPut. */
            public kvPut?: (dmcn.relay.IMailboxKvPutOp|null);

            /** MailboxOp kvGet. */
            public kvGet?: (dmcn.relay.IMailboxKvGetOp|null);

            /** MailboxOp kvList. */
            public kvList?: (dmcn.relay.IMailboxKvListOp|null);

            /** MailboxOp kvDelete. */
            public kvDelete?: (dmcn.relay.IMailboxKvDeleteOp|null);

            /** MailboxOp kvStat. */
            public kvStat?: (dmcn.relay.IMailboxKvStatOp|null);

            /** MailboxOp op. */
            public op?: ("list"|"body"|"delete"|"kvPut"|"kvGet"|"kvList"|"kvDelete"|"kvStat");

            /**
             * Creates a new MailboxOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxOp): dmcn.relay.MailboxOp;

            /**
             * Encodes the specified MailboxOp message. Does not implicitly {@link dmcn.relay.MailboxOp.verify|verify} messages.
             * @param message MailboxOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxOp.verify|verify} messages.
             * @param message MailboxOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxOp;

            /**
             * Decodes a MailboxOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxOp;

            /**
             * Verifies a MailboxOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxOp;

            /**
             * Creates a plain object from a MailboxOp message. Also converts values to other types if specified.
             * @param message MailboxOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxListOp. */
        interface IMailboxListOp {

            /** MailboxListOp limit */
            limit?: (number|null);

            /** MailboxListOp cursor */
            cursor?: (Uint8Array|null);
        }

        /** Represents a MailboxListOp. */
        class MailboxListOp implements IMailboxListOp {

            /**
             * Constructs a new MailboxListOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxListOp);

            /** MailboxListOp limit. */
            public limit: number;

            /** MailboxListOp cursor. */
            public cursor: Uint8Array;

            /**
             * Creates a new MailboxListOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxListOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxListOp): dmcn.relay.MailboxListOp;

            /**
             * Encodes the specified MailboxListOp message. Does not implicitly {@link dmcn.relay.MailboxListOp.verify|verify} messages.
             * @param message MailboxListOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxListOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxListOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxListOp.verify|verify} messages.
             * @param message MailboxListOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxListOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxListOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxListOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxListOp;

            /**
             * Decodes a MailboxListOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxListOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxListOp;

            /**
             * Verifies a MailboxListOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxListOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxListOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxListOp;

            /**
             * Creates a plain object from a MailboxListOp message. Also converts values to other types if specified.
             * @param message MailboxListOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxListOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxListOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxListOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxBodyOp. */
        interface IMailboxBodyOp {

            /** MailboxBodyOp hash */
            hash?: (Uint8Array|null);
        }

        /** Represents a MailboxBodyOp. */
        class MailboxBodyOp implements IMailboxBodyOp {

            /**
             * Constructs a new MailboxBodyOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxBodyOp);

            /** MailboxBodyOp hash. */
            public hash: Uint8Array;

            /**
             * Creates a new MailboxBodyOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxBodyOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxBodyOp): dmcn.relay.MailboxBodyOp;

            /**
             * Encodes the specified MailboxBodyOp message. Does not implicitly {@link dmcn.relay.MailboxBodyOp.verify|verify} messages.
             * @param message MailboxBodyOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxBodyOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxBodyOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxBodyOp.verify|verify} messages.
             * @param message MailboxBodyOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxBodyOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxBodyOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxBodyOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxBodyOp;

            /**
             * Decodes a MailboxBodyOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxBodyOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxBodyOp;

            /**
             * Verifies a MailboxBodyOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxBodyOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxBodyOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxBodyOp;

            /**
             * Creates a plain object from a MailboxBodyOp message. Also converts values to other types if specified.
             * @param message MailboxBodyOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxBodyOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxBodyOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxBodyOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxDeleteOp. */
        interface IMailboxDeleteOp {

            /** MailboxDeleteOp hash */
            hash?: (Uint8Array|null);
        }

        /** Represents a MailboxDeleteOp. */
        class MailboxDeleteOp implements IMailboxDeleteOp {

            /**
             * Constructs a new MailboxDeleteOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxDeleteOp);

            /** MailboxDeleteOp hash. */
            public hash: Uint8Array;

            /**
             * Creates a new MailboxDeleteOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxDeleteOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxDeleteOp): dmcn.relay.MailboxDeleteOp;

            /**
             * Encodes the specified MailboxDeleteOp message. Does not implicitly {@link dmcn.relay.MailboxDeleteOp.verify|verify} messages.
             * @param message MailboxDeleteOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxDeleteOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxDeleteOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxDeleteOp.verify|verify} messages.
             * @param message MailboxDeleteOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxDeleteOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxDeleteOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxDeleteOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxDeleteOp;

            /**
             * Decodes a MailboxDeleteOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxDeleteOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxDeleteOp;

            /**
             * Verifies a MailboxDeleteOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxDeleteOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxDeleteOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxDeleteOp;

            /**
             * Creates a plain object from a MailboxDeleteOp message. Also converts values to other types if specified.
             * @param message MailboxDeleteOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxDeleteOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxDeleteOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxDeleteOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxListResponse. */
        interface IMailboxListResponse {

            /** MailboxListResponse entries */
            entries?: (dmcn.relay.IMailboxEntry[]|null);

            /** MailboxListResponse nextCursor */
            nextCursor?: (Uint8Array|null);
        }

        /** Represents a MailboxListResponse. */
        class MailboxListResponse implements IMailboxListResponse {

            /**
             * Constructs a new MailboxListResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxListResponse);

            /** MailboxListResponse entries. */
            public entries: dmcn.relay.IMailboxEntry[];

            /** MailboxListResponse nextCursor. */
            public nextCursor: Uint8Array;

            /**
             * Creates a new MailboxListResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxListResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxListResponse): dmcn.relay.MailboxListResponse;

            /**
             * Encodes the specified MailboxListResponse message. Does not implicitly {@link dmcn.relay.MailboxListResponse.verify|verify} messages.
             * @param message MailboxListResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxListResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxListResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxListResponse.verify|verify} messages.
             * @param message MailboxListResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxListResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxListResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxListResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxListResponse;

            /**
             * Decodes a MailboxListResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxListResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxListResponse;

            /**
             * Verifies a MailboxListResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxListResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxListResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxListResponse;

            /**
             * Creates a plain object from a MailboxListResponse message. Also converts values to other types if specified.
             * @param message MailboxListResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxListResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxListResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxListResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxBodyHeader. */
        interface IMailboxBodyHeader {

            /** MailboxBodyHeader bodyNonce */
            bodyNonce?: (Uint8Array|null);

            /** MailboxBodyHeader bodyTag */
            bodyTag?: (Uint8Array|null);

            /** MailboxBodyHeader bodySizeClass */
            bodySizeClass?: (number|null);

            /** MailboxBodyHeader bodyTotalSize */
            bodyTotalSize?: (number|Long|null);
        }

        /** Represents a MailboxBodyHeader. */
        class MailboxBodyHeader implements IMailboxBodyHeader {

            /**
             * Constructs a new MailboxBodyHeader.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxBodyHeader);

            /** MailboxBodyHeader bodyNonce. */
            public bodyNonce: Uint8Array;

            /** MailboxBodyHeader bodyTag. */
            public bodyTag: Uint8Array;

            /** MailboxBodyHeader bodySizeClass. */
            public bodySizeClass: number;

            /** MailboxBodyHeader bodyTotalSize. */
            public bodyTotalSize: (number|Long);

            /**
             * Creates a new MailboxBodyHeader instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxBodyHeader instance
             */
            public static create(properties?: dmcn.relay.IMailboxBodyHeader): dmcn.relay.MailboxBodyHeader;

            /**
             * Encodes the specified MailboxBodyHeader message. Does not implicitly {@link dmcn.relay.MailboxBodyHeader.verify|verify} messages.
             * @param message MailboxBodyHeader message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxBodyHeader, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxBodyHeader message, length delimited. Does not implicitly {@link dmcn.relay.MailboxBodyHeader.verify|verify} messages.
             * @param message MailboxBodyHeader message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxBodyHeader, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxBodyHeader message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxBodyHeader
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxBodyHeader;

            /**
             * Decodes a MailboxBodyHeader message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxBodyHeader
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxBodyHeader;

            /**
             * Verifies a MailboxBodyHeader message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxBodyHeader message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxBodyHeader
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxBodyHeader;

            /**
             * Creates a plain object from a MailboxBodyHeader message. Also converts values to other types if specified.
             * @param message MailboxBodyHeader
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxBodyHeader, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxBodyHeader to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxBodyHeader
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxDeleteResponse. */
        interface IMailboxDeleteResponse {

            /** MailboxDeleteResponse success */
            success?: (boolean|null);
        }

        /** Represents a MailboxDeleteResponse. */
        class MailboxDeleteResponse implements IMailboxDeleteResponse {

            /**
             * Constructs a new MailboxDeleteResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxDeleteResponse);

            /** MailboxDeleteResponse success. */
            public success: boolean;

            /**
             * Creates a new MailboxDeleteResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxDeleteResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxDeleteResponse): dmcn.relay.MailboxDeleteResponse;

            /**
             * Encodes the specified MailboxDeleteResponse message. Does not implicitly {@link dmcn.relay.MailboxDeleteResponse.verify|verify} messages.
             * @param message MailboxDeleteResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxDeleteResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxDeleteResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxDeleteResponse.verify|verify} messages.
             * @param message MailboxDeleteResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxDeleteResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxDeleteResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxDeleteResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxDeleteResponse;

            /**
             * Decodes a MailboxDeleteResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxDeleteResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxDeleteResponse;

            /**
             * Verifies a MailboxDeleteResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxDeleteResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxDeleteResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxDeleteResponse;

            /**
             * Creates a plain object from a MailboxDeleteResponse message. Also converts values to other types if specified.
             * @param message MailboxDeleteResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxDeleteResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxDeleteResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxDeleteResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a StoreInit. */
        interface IStoreInit {

            /** StoreInit senderAddress */
            senderAddress?: (string|null);

            /** StoreInit senderSignature */
            senderSignature?: (Uint8Array|null);

            /** StoreInit version */
            version?: (number|null);

            /** StoreInit messageId */
            messageId?: (Uint8Array|null);

            /** StoreInit createdAt */
            createdAt?: (number|Long|null);

            /** StoreInit recipients */
            recipients?: (dmcn.message.IRecipientRecord[]|null);

            /** StoreInit encryptedHeader */
            encryptedHeader?: (Uint8Array|null);

            /** StoreInit headerNonce */
            headerNonce?: (Uint8Array|null);

            /** StoreInit headerTag */
            headerTag?: (Uint8Array|null);

            /** StoreInit headerSizeClass */
            headerSizeClass?: (number|null);

            /** StoreInit bodyNonce */
            bodyNonce?: (Uint8Array|null);

            /** StoreInit bodyTag */
            bodyTag?: (Uint8Array|null);

            /** StoreInit bodySizeClass */
            bodySizeClass?: (number|null);

            /** StoreInit bodyTotalSize */
            bodyTotalSize?: (number|Long|null);

            /** StoreInit bodyContentAddress */
            bodyContentAddress?: (Uint8Array|null);
        }

        /** Represents a StoreInit. */
        class StoreInit implements IStoreInit {

            /**
             * Constructs a new StoreInit.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IStoreInit);

            /** StoreInit senderAddress. */
            public senderAddress: string;

            /** StoreInit senderSignature. */
            public senderSignature: Uint8Array;

            /** StoreInit version. */
            public version: number;

            /** StoreInit messageId. */
            public messageId: Uint8Array;

            /** StoreInit createdAt. */
            public createdAt: (number|Long);

            /** StoreInit recipients. */
            public recipients: dmcn.message.IRecipientRecord[];

            /** StoreInit encryptedHeader. */
            public encryptedHeader: Uint8Array;

            /** StoreInit headerNonce. */
            public headerNonce: Uint8Array;

            /** StoreInit headerTag. */
            public headerTag: Uint8Array;

            /** StoreInit headerSizeClass. */
            public headerSizeClass: number;

            /** StoreInit bodyNonce. */
            public bodyNonce: Uint8Array;

            /** StoreInit bodyTag. */
            public bodyTag: Uint8Array;

            /** StoreInit bodySizeClass. */
            public bodySizeClass: number;

            /** StoreInit bodyTotalSize. */
            public bodyTotalSize: (number|Long);

            /** StoreInit bodyContentAddress. */
            public bodyContentAddress: Uint8Array;

            /**
             * Creates a new StoreInit instance using the specified properties.
             * @param [properties] Properties to set
             * @returns StoreInit instance
             */
            public static create(properties?: dmcn.relay.IStoreInit): dmcn.relay.StoreInit;

            /**
             * Encodes the specified StoreInit message. Does not implicitly {@link dmcn.relay.StoreInit.verify|verify} messages.
             * @param message StoreInit message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IStoreInit, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified StoreInit message, length delimited. Does not implicitly {@link dmcn.relay.StoreInit.verify|verify} messages.
             * @param message StoreInit message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IStoreInit, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a StoreInit message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns StoreInit
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.StoreInit;

            /**
             * Decodes a StoreInit message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns StoreInit
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.StoreInit;

            /**
             * Verifies a StoreInit message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a StoreInit message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns StoreInit
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.StoreInit;

            /**
             * Creates a plain object from a StoreInit message. Also converts values to other types if specified.
             * @param message StoreInit
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.StoreInit, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this StoreInit to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for StoreInit
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvPutOp. */
        interface IMailboxKvPutOp {

            /** MailboxKvPutOp key */
            key?: (string|null);

            /** MailboxKvPutOp sealed */
            sealed?: (Uint8Array|null);

            /** MailboxKvPutOp expectedVersion */
            expectedVersion?: (number|Long|null);
        }

        /** Represents a MailboxKvPutOp. */
        class MailboxKvPutOp implements IMailboxKvPutOp {

            /**
             * Constructs a new MailboxKvPutOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvPutOp);

            /** MailboxKvPutOp key. */
            public key: string;

            /** MailboxKvPutOp sealed. */
            public sealed: Uint8Array;

            /** MailboxKvPutOp expectedVersion. */
            public expectedVersion: (number|Long);

            /**
             * Creates a new MailboxKvPutOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvPutOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvPutOp): dmcn.relay.MailboxKvPutOp;

            /**
             * Encodes the specified MailboxKvPutOp message. Does not implicitly {@link dmcn.relay.MailboxKvPutOp.verify|verify} messages.
             * @param message MailboxKvPutOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvPutOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvPutOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvPutOp.verify|verify} messages.
             * @param message MailboxKvPutOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvPutOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvPutOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvPutOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvPutOp;

            /**
             * Decodes a MailboxKvPutOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvPutOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvPutOp;

            /**
             * Verifies a MailboxKvPutOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvPutOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvPutOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvPutOp;

            /**
             * Creates a plain object from a MailboxKvPutOp message. Also converts values to other types if specified.
             * @param message MailboxKvPutOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvPutOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvPutOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvPutOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvGetOp. */
        interface IMailboxKvGetOp {

            /** MailboxKvGetOp key */
            key?: (string|null);
        }

        /** Represents a MailboxKvGetOp. */
        class MailboxKvGetOp implements IMailboxKvGetOp {

            /**
             * Constructs a new MailboxKvGetOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvGetOp);

            /** MailboxKvGetOp key. */
            public key: string;

            /**
             * Creates a new MailboxKvGetOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvGetOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvGetOp): dmcn.relay.MailboxKvGetOp;

            /**
             * Encodes the specified MailboxKvGetOp message. Does not implicitly {@link dmcn.relay.MailboxKvGetOp.verify|verify} messages.
             * @param message MailboxKvGetOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvGetOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvGetOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvGetOp.verify|verify} messages.
             * @param message MailboxKvGetOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvGetOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvGetOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvGetOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvGetOp;

            /**
             * Decodes a MailboxKvGetOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvGetOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvGetOp;

            /**
             * Verifies a MailboxKvGetOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvGetOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvGetOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvGetOp;

            /**
             * Creates a plain object from a MailboxKvGetOp message. Also converts values to other types if specified.
             * @param message MailboxKvGetOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvGetOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvGetOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvGetOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvListOp. */
        interface IMailboxKvListOp {

            /** MailboxKvListOp prefix */
            prefix?: (string|null);

            /** MailboxKvListOp limit */
            limit?: (number|null);

            /** MailboxKvListOp cursor */
            cursor?: (Uint8Array|null);

            /** MailboxKvListOp values */
            values?: (boolean|null);
        }

        /** Represents a MailboxKvListOp. */
        class MailboxKvListOp implements IMailboxKvListOp {

            /**
             * Constructs a new MailboxKvListOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvListOp);

            /** MailboxKvListOp prefix. */
            public prefix: string;

            /** MailboxKvListOp limit. */
            public limit: number;

            /** MailboxKvListOp cursor. */
            public cursor: Uint8Array;

            /** MailboxKvListOp values. */
            public values: boolean;

            /**
             * Creates a new MailboxKvListOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvListOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvListOp): dmcn.relay.MailboxKvListOp;

            /**
             * Encodes the specified MailboxKvListOp message. Does not implicitly {@link dmcn.relay.MailboxKvListOp.verify|verify} messages.
             * @param message MailboxKvListOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvListOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvListOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvListOp.verify|verify} messages.
             * @param message MailboxKvListOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvListOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvListOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvListOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvListOp;

            /**
             * Decodes a MailboxKvListOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvListOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvListOp;

            /**
             * Verifies a MailboxKvListOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvListOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvListOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvListOp;

            /**
             * Creates a plain object from a MailboxKvListOp message. Also converts values to other types if specified.
             * @param message MailboxKvListOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvListOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvListOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvListOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvDeleteOp. */
        interface IMailboxKvDeleteOp {

            /** MailboxKvDeleteOp key */
            key?: (string|null);
        }

        /** Represents a MailboxKvDeleteOp. */
        class MailboxKvDeleteOp implements IMailboxKvDeleteOp {

            /**
             * Constructs a new MailboxKvDeleteOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvDeleteOp);

            /** MailboxKvDeleteOp key. */
            public key: string;

            /**
             * Creates a new MailboxKvDeleteOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvDeleteOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvDeleteOp): dmcn.relay.MailboxKvDeleteOp;

            /**
             * Encodes the specified MailboxKvDeleteOp message. Does not implicitly {@link dmcn.relay.MailboxKvDeleteOp.verify|verify} messages.
             * @param message MailboxKvDeleteOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvDeleteOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvDeleteOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvDeleteOp.verify|verify} messages.
             * @param message MailboxKvDeleteOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvDeleteOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvDeleteOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvDeleteOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvDeleteOp;

            /**
             * Decodes a MailboxKvDeleteOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvDeleteOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvDeleteOp;

            /**
             * Verifies a MailboxKvDeleteOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvDeleteOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvDeleteOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvDeleteOp;

            /**
             * Creates a plain object from a MailboxKvDeleteOp message. Also converts values to other types if specified.
             * @param message MailboxKvDeleteOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvDeleteOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvDeleteOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvDeleteOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvStatOp. */
        interface IMailboxKvStatOp {
        }

        /** Represents a MailboxKvStatOp. */
        class MailboxKvStatOp implements IMailboxKvStatOp {

            /**
             * Constructs a new MailboxKvStatOp.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvStatOp);

            /**
             * Creates a new MailboxKvStatOp instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvStatOp instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvStatOp): dmcn.relay.MailboxKvStatOp;

            /**
             * Encodes the specified MailboxKvStatOp message. Does not implicitly {@link dmcn.relay.MailboxKvStatOp.verify|verify} messages.
             * @param message MailboxKvStatOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvStatOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvStatOp message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvStatOp.verify|verify} messages.
             * @param message MailboxKvStatOp message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvStatOp, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvStatOp message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvStatOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvStatOp;

            /**
             * Decodes a MailboxKvStatOp message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvStatOp
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvStatOp;

            /**
             * Verifies a MailboxKvStatOp message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvStatOp message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvStatOp
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvStatOp;

            /**
             * Creates a plain object from a MailboxKvStatOp message. Also converts values to other types if specified.
             * @param message MailboxKvStatOp
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvStatOp, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvStatOp to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvStatOp
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvPutResponse. */
        interface IMailboxKvPutResponse {

            /** MailboxKvPutResponse success */
            success?: (boolean|null);

            /** MailboxKvPutResponse version */
            version?: (number|Long|null);
        }

        /** Represents a MailboxKvPutResponse. */
        class MailboxKvPutResponse implements IMailboxKvPutResponse {

            /**
             * Constructs a new MailboxKvPutResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvPutResponse);

            /** MailboxKvPutResponse success. */
            public success: boolean;

            /** MailboxKvPutResponse version. */
            public version: (number|Long);

            /**
             * Creates a new MailboxKvPutResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvPutResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvPutResponse): dmcn.relay.MailboxKvPutResponse;

            /**
             * Encodes the specified MailboxKvPutResponse message. Does not implicitly {@link dmcn.relay.MailboxKvPutResponse.verify|verify} messages.
             * @param message MailboxKvPutResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvPutResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvPutResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvPutResponse.verify|verify} messages.
             * @param message MailboxKvPutResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvPutResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvPutResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvPutResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvPutResponse;

            /**
             * Decodes a MailboxKvPutResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvPutResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvPutResponse;

            /**
             * Verifies a MailboxKvPutResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvPutResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvPutResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvPutResponse;

            /**
             * Creates a plain object from a MailboxKvPutResponse message. Also converts values to other types if specified.
             * @param message MailboxKvPutResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvPutResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvPutResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvPutResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvGetResponse. */
        interface IMailboxKvGetResponse {

            /** MailboxKvGetResponse found */
            found?: (boolean|null);

            /** MailboxKvGetResponse sealed */
            sealed?: (Uint8Array|null);

            /** MailboxKvGetResponse version */
            version?: (number|Long|null);
        }

        /** Represents a MailboxKvGetResponse. */
        class MailboxKvGetResponse implements IMailboxKvGetResponse {

            /**
             * Constructs a new MailboxKvGetResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvGetResponse);

            /** MailboxKvGetResponse found. */
            public found: boolean;

            /** MailboxKvGetResponse sealed. */
            public sealed: Uint8Array;

            /** MailboxKvGetResponse version. */
            public version: (number|Long);

            /**
             * Creates a new MailboxKvGetResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvGetResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvGetResponse): dmcn.relay.MailboxKvGetResponse;

            /**
             * Encodes the specified MailboxKvGetResponse message. Does not implicitly {@link dmcn.relay.MailboxKvGetResponse.verify|verify} messages.
             * @param message MailboxKvGetResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvGetResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvGetResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvGetResponse.verify|verify} messages.
             * @param message MailboxKvGetResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvGetResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvGetResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvGetResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvGetResponse;

            /**
             * Decodes a MailboxKvGetResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvGetResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvGetResponse;

            /**
             * Verifies a MailboxKvGetResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvGetResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvGetResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvGetResponse;

            /**
             * Creates a plain object from a MailboxKvGetResponse message. Also converts values to other types if specified.
             * @param message MailboxKvGetResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvGetResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvGetResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvGetResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvItem. */
        interface IMailboxKvItem {

            /** MailboxKvItem key */
            key?: (string|null);

            /** MailboxKvItem sealed */
            sealed?: (Uint8Array|null);

            /** MailboxKvItem version */
            version?: (number|Long|null);
        }

        /** Represents a MailboxKvItem. */
        class MailboxKvItem implements IMailboxKvItem {

            /**
             * Constructs a new MailboxKvItem.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvItem);

            /** MailboxKvItem key. */
            public key: string;

            /** MailboxKvItem sealed. */
            public sealed: Uint8Array;

            /** MailboxKvItem version. */
            public version: (number|Long);

            /**
             * Creates a new MailboxKvItem instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvItem instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvItem): dmcn.relay.MailboxKvItem;

            /**
             * Encodes the specified MailboxKvItem message. Does not implicitly {@link dmcn.relay.MailboxKvItem.verify|verify} messages.
             * @param message MailboxKvItem message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvItem, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvItem message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvItem.verify|verify} messages.
             * @param message MailboxKvItem message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvItem, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvItem message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvItem
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvItem;

            /**
             * Decodes a MailboxKvItem message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvItem
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvItem;

            /**
             * Verifies a MailboxKvItem message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvItem message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvItem
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvItem;

            /**
             * Creates a plain object from a MailboxKvItem message. Also converts values to other types if specified.
             * @param message MailboxKvItem
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvItem, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvItem to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvItem
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvListResponse. */
        interface IMailboxKvListResponse {

            /** MailboxKvListResponse items */
            items?: (dmcn.relay.IMailboxKvItem[]|null);

            /** MailboxKvListResponse nextCursor */
            nextCursor?: (Uint8Array|null);
        }

        /** Represents a MailboxKvListResponse. */
        class MailboxKvListResponse implements IMailboxKvListResponse {

            /**
             * Constructs a new MailboxKvListResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvListResponse);

            /** MailboxKvListResponse items. */
            public items: dmcn.relay.IMailboxKvItem[];

            /** MailboxKvListResponse nextCursor. */
            public nextCursor: Uint8Array;

            /**
             * Creates a new MailboxKvListResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvListResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvListResponse): dmcn.relay.MailboxKvListResponse;

            /**
             * Encodes the specified MailboxKvListResponse message. Does not implicitly {@link dmcn.relay.MailboxKvListResponse.verify|verify} messages.
             * @param message MailboxKvListResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvListResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvListResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvListResponse.verify|verify} messages.
             * @param message MailboxKvListResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvListResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvListResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvListResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvListResponse;

            /**
             * Decodes a MailboxKvListResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvListResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvListResponse;

            /**
             * Verifies a MailboxKvListResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvListResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvListResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvListResponse;

            /**
             * Creates a plain object from a MailboxKvListResponse message. Also converts values to other types if specified.
             * @param message MailboxKvListResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvListResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvListResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvListResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvDeleteResponse. */
        interface IMailboxKvDeleteResponse {

            /** MailboxKvDeleteResponse success */
            success?: (boolean|null);
        }

        /** Represents a MailboxKvDeleteResponse. */
        class MailboxKvDeleteResponse implements IMailboxKvDeleteResponse {

            /**
             * Constructs a new MailboxKvDeleteResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvDeleteResponse);

            /** MailboxKvDeleteResponse success. */
            public success: boolean;

            /**
             * Creates a new MailboxKvDeleteResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvDeleteResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvDeleteResponse): dmcn.relay.MailboxKvDeleteResponse;

            /**
             * Encodes the specified MailboxKvDeleteResponse message. Does not implicitly {@link dmcn.relay.MailboxKvDeleteResponse.verify|verify} messages.
             * @param message MailboxKvDeleteResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvDeleteResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvDeleteResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvDeleteResponse.verify|verify} messages.
             * @param message MailboxKvDeleteResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvDeleteResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvDeleteResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvDeleteResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvDeleteResponse;

            /**
             * Decodes a MailboxKvDeleteResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvDeleteResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvDeleteResponse;

            /**
             * Verifies a MailboxKvDeleteResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvDeleteResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvDeleteResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvDeleteResponse;

            /**
             * Creates a plain object from a MailboxKvDeleteResponse message. Also converts values to other types if specified.
             * @param message MailboxKvDeleteResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvDeleteResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvDeleteResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvDeleteResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a MailboxKvStatResponse. */
        interface IMailboxKvStatResponse {

            /** MailboxKvStatResponse usedBytes */
            usedBytes?: (number|Long|null);

            /** MailboxKvStatResponse quotaBytes */
            quotaBytes?: (number|Long|null);

            /** MailboxKvStatResponse count */
            count?: (number|Long|null);
        }

        /** Represents a MailboxKvStatResponse. */
        class MailboxKvStatResponse implements IMailboxKvStatResponse {

            /**
             * Constructs a new MailboxKvStatResponse.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.relay.IMailboxKvStatResponse);

            /** MailboxKvStatResponse usedBytes. */
            public usedBytes: (number|Long);

            /** MailboxKvStatResponse quotaBytes. */
            public quotaBytes: (number|Long);

            /** MailboxKvStatResponse count. */
            public count: (number|Long);

            /**
             * Creates a new MailboxKvStatResponse instance using the specified properties.
             * @param [properties] Properties to set
             * @returns MailboxKvStatResponse instance
             */
            public static create(properties?: dmcn.relay.IMailboxKvStatResponse): dmcn.relay.MailboxKvStatResponse;

            /**
             * Encodes the specified MailboxKvStatResponse message. Does not implicitly {@link dmcn.relay.MailboxKvStatResponse.verify|verify} messages.
             * @param message MailboxKvStatResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.relay.IMailboxKvStatResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified MailboxKvStatResponse message, length delimited. Does not implicitly {@link dmcn.relay.MailboxKvStatResponse.verify|verify} messages.
             * @param message MailboxKvStatResponse message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.relay.IMailboxKvStatResponse, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a MailboxKvStatResponse message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns MailboxKvStatResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.relay.MailboxKvStatResponse;

            /**
             * Decodes a MailboxKvStatResponse message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns MailboxKvStatResponse
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.relay.MailboxKvStatResponse;

            /**
             * Verifies a MailboxKvStatResponse message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a MailboxKvStatResponse message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns MailboxKvStatResponse
             */
            public static fromObject(object: { [k: string]: any }): dmcn.relay.MailboxKvStatResponse;

            /**
             * Creates a plain object from a MailboxKvStatResponse message. Also converts values to other types if specified.
             * @param message MailboxKvStatResponse
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.relay.MailboxKvStatResponse, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this MailboxKvStatResponse to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for MailboxKvStatResponse
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }
    }

    /** Namespace bridge. */
    namespace bridge {

        /** BridgeTrustTier enum. */
        enum BridgeTrustTier {
            BRIDGE_TRUST_TIER_UNSPECIFIED = 0,
            BRIDGE_TRUST_TIER_VERIFIED_LEGACY = 1,
            BRIDGE_TRUST_TIER_UNVERIFIED_LEGACY = 2,
            BRIDGE_TRUST_TIER_SUSPICIOUS = 3
        }

        /** SPFResult enum. */
        enum SPFResult {
            SPF_RESULT_UNSPECIFIED = 0,
            SPF_RESULT_PASS = 1,
            SPF_RESULT_FAIL = 2,
            SPF_RESULT_SOFTFAIL = 3,
            SPF_RESULT_NEUTRAL = 4
        }

        /** DKIMResult enum. */
        enum DKIMResult {
            DKIM_RESULT_UNSPECIFIED = 0,
            DKIM_RESULT_PASS = 1,
            DKIM_RESULT_FAIL = 2
        }

        /** DMARCResult enum. */
        enum DMARCResult {
            DMARC_RESULT_UNSPECIFIED = 0,
            DMARC_RESULT_PASS = 1,
            DMARC_RESULT_FAIL = 2
        }

        /** Properties of a BridgeClassificationRecord. */
        interface IBridgeClassificationRecord {

            /** BridgeClassificationRecord bridgeAddress */
            bridgeAddress?: (string|null);

            /** BridgeClassificationRecord bridgePublicKey */
            bridgePublicKey?: (Uint8Array|null);

            /** BridgeClassificationRecord smtpFrom */
            smtpFrom?: (string|null);

            /** BridgeClassificationRecord smtpSenderIp */
            smtpSenderIp?: (string|null);

            /** BridgeClassificationRecord spfResult */
            spfResult?: (dmcn.bridge.SPFResult|null);

            /** BridgeClassificationRecord dkimResult */
            dkimResult?: (dmcn.bridge.DKIMResult|null);

            /** BridgeClassificationRecord dmarcResult */
            dmarcResult?: (dmcn.bridge.DMARCResult|null);

            /** BridgeClassificationRecord reputationScore */
            reputationScore?: (number|null);

            /** BridgeClassificationRecord trustTier */
            trustTier?: (dmcn.bridge.BridgeTrustTier|null);

            /** BridgeClassificationRecord classifiedAt */
            classifiedAt?: (number|Long|null);

            /** BridgeClassificationRecord bridgeSignature */
            bridgeSignature?: (Uint8Array|null);

            /** BridgeClassificationRecord bridgeCredential */
            bridgeCredential?: (dmcn.identity.ICredential|null);
        }

        /** Represents a BridgeClassificationRecord. */
        class BridgeClassificationRecord implements IBridgeClassificationRecord {

            /**
             * Constructs a new BridgeClassificationRecord.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.bridge.IBridgeClassificationRecord);

            /** BridgeClassificationRecord bridgeAddress. */
            public bridgeAddress: string;

            /** BridgeClassificationRecord bridgePublicKey. */
            public bridgePublicKey: Uint8Array;

            /** BridgeClassificationRecord smtpFrom. */
            public smtpFrom: string;

            /** BridgeClassificationRecord smtpSenderIp. */
            public smtpSenderIp: string;

            /** BridgeClassificationRecord spfResult. */
            public spfResult: dmcn.bridge.SPFResult;

            /** BridgeClassificationRecord dkimResult. */
            public dkimResult: dmcn.bridge.DKIMResult;

            /** BridgeClassificationRecord dmarcResult. */
            public dmarcResult: dmcn.bridge.DMARCResult;

            /** BridgeClassificationRecord reputationScore. */
            public reputationScore: number;

            /** BridgeClassificationRecord trustTier. */
            public trustTier: dmcn.bridge.BridgeTrustTier;

            /** BridgeClassificationRecord classifiedAt. */
            public classifiedAt: (number|Long);

            /** BridgeClassificationRecord bridgeSignature. */
            public bridgeSignature: Uint8Array;

            /** BridgeClassificationRecord bridgeCredential. */
            public bridgeCredential?: (dmcn.identity.ICredential|null);

            /**
             * Creates a new BridgeClassificationRecord instance using the specified properties.
             * @param [properties] Properties to set
             * @returns BridgeClassificationRecord instance
             */
            public static create(properties?: dmcn.bridge.IBridgeClassificationRecord): dmcn.bridge.BridgeClassificationRecord;

            /**
             * Encodes the specified BridgeClassificationRecord message. Does not implicitly {@link dmcn.bridge.BridgeClassificationRecord.verify|verify} messages.
             * @param message BridgeClassificationRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.bridge.IBridgeClassificationRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified BridgeClassificationRecord message, length delimited. Does not implicitly {@link dmcn.bridge.BridgeClassificationRecord.verify|verify} messages.
             * @param message BridgeClassificationRecord message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.bridge.IBridgeClassificationRecord, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a BridgeClassificationRecord message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns BridgeClassificationRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.bridge.BridgeClassificationRecord;

            /**
             * Decodes a BridgeClassificationRecord message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns BridgeClassificationRecord
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.bridge.BridgeClassificationRecord;

            /**
             * Verifies a BridgeClassificationRecord message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a BridgeClassificationRecord message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns BridgeClassificationRecord
             */
            public static fromObject(object: { [k: string]: any }): dmcn.bridge.BridgeClassificationRecord;

            /**
             * Creates a plain object from a BridgeClassificationRecord message. Also converts values to other types if specified.
             * @param message BridgeClassificationRecord
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.bridge.BridgeClassificationRecord, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this BridgeClassificationRecord to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for BridgeClassificationRecord
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }

        /** Properties of a BridgeDeliveryReceipt. */
        interface IBridgeDeliveryReceipt {

            /** BridgeDeliveryReceipt originalMessageId */
            originalMessageId?: (Uint8Array|null);

            /** BridgeDeliveryReceipt recipientEmail */
            recipientEmail?: (string|null);

            /** BridgeDeliveryReceipt bridgeAddress */
            bridgeAddress?: (string|null);

            /** BridgeDeliveryReceipt deliveredAt */
            deliveredAt?: (number|Long|null);

            /** BridgeDeliveryReceipt success */
            success?: (boolean|null);

            /** BridgeDeliveryReceipt errorDetail */
            errorDetail?: (string|null);

            /** BridgeDeliveryReceipt bridgeSignature */
            bridgeSignature?: (Uint8Array|null);

            /** BridgeDeliveryReceipt bridgeCredential */
            bridgeCredential?: (dmcn.identity.ICredential|null);
        }

        /** Represents a BridgeDeliveryReceipt. */
        class BridgeDeliveryReceipt implements IBridgeDeliveryReceipt {

            /**
             * Constructs a new BridgeDeliveryReceipt.
             * @param [properties] Properties to set
             */
            constructor(properties?: dmcn.bridge.IBridgeDeliveryReceipt);

            /** BridgeDeliveryReceipt originalMessageId. */
            public originalMessageId: Uint8Array;

            /** BridgeDeliveryReceipt recipientEmail. */
            public recipientEmail: string;

            /** BridgeDeliveryReceipt bridgeAddress. */
            public bridgeAddress: string;

            /** BridgeDeliveryReceipt deliveredAt. */
            public deliveredAt: (number|Long);

            /** BridgeDeliveryReceipt success. */
            public success: boolean;

            /** BridgeDeliveryReceipt errorDetail. */
            public errorDetail: string;

            /** BridgeDeliveryReceipt bridgeSignature. */
            public bridgeSignature: Uint8Array;

            /** BridgeDeliveryReceipt bridgeCredential. */
            public bridgeCredential?: (dmcn.identity.ICredential|null);

            /**
             * Creates a new BridgeDeliveryReceipt instance using the specified properties.
             * @param [properties] Properties to set
             * @returns BridgeDeliveryReceipt instance
             */
            public static create(properties?: dmcn.bridge.IBridgeDeliveryReceipt): dmcn.bridge.BridgeDeliveryReceipt;

            /**
             * Encodes the specified BridgeDeliveryReceipt message. Does not implicitly {@link dmcn.bridge.BridgeDeliveryReceipt.verify|verify} messages.
             * @param message BridgeDeliveryReceipt message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encode(message: dmcn.bridge.IBridgeDeliveryReceipt, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Encodes the specified BridgeDeliveryReceipt message, length delimited. Does not implicitly {@link dmcn.bridge.BridgeDeliveryReceipt.verify|verify} messages.
             * @param message BridgeDeliveryReceipt message or plain object to encode
             * @param [writer] Writer to encode to
             * @returns Writer
             */
            public static encodeDelimited(message: dmcn.bridge.IBridgeDeliveryReceipt, writer?: $protobuf.Writer): $protobuf.Writer;

            /**
             * Decodes a BridgeDeliveryReceipt message from the specified reader or buffer.
             * @param reader Reader or buffer to decode from
             * @param [length] Message length if known beforehand
             * @returns BridgeDeliveryReceipt
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decode(reader: ($protobuf.Reader|Uint8Array), length?: number): dmcn.bridge.BridgeDeliveryReceipt;

            /**
             * Decodes a BridgeDeliveryReceipt message from the specified reader or buffer, length delimited.
             * @param reader Reader or buffer to decode from
             * @returns BridgeDeliveryReceipt
             * @throws {Error} If the payload is not a reader or valid buffer
             * @throws {$protobuf.util.ProtocolError} If required fields are missing
             */
            public static decodeDelimited(reader: ($protobuf.Reader|Uint8Array)): dmcn.bridge.BridgeDeliveryReceipt;

            /**
             * Verifies a BridgeDeliveryReceipt message.
             * @param message Plain object to verify
             * @returns `null` if valid, otherwise the reason why it is not
             */
            public static verify(message: { [k: string]: any }): (string|null);

            /**
             * Creates a BridgeDeliveryReceipt message from a plain object. Also converts values to their respective internal types.
             * @param object Plain object
             * @returns BridgeDeliveryReceipt
             */
            public static fromObject(object: { [k: string]: any }): dmcn.bridge.BridgeDeliveryReceipt;

            /**
             * Creates a plain object from a BridgeDeliveryReceipt message. Also converts values to other types if specified.
             * @param message BridgeDeliveryReceipt
             * @param [options] Conversion options
             * @returns Plain object
             */
            public static toObject(message: dmcn.bridge.BridgeDeliveryReceipt, options?: $protobuf.IConversionOptions): { [k: string]: any };

            /**
             * Converts this BridgeDeliveryReceipt to JSON.
             * @returns JSON object
             */
            public toJSON(): { [k: string]: any };

            /**
             * Gets the default type url for BridgeDeliveryReceipt
             * @param [typeUrlPrefix] your custom typeUrlPrefix(default "type.googleapis.com")
             * @returns The default type url
             */
            public static getTypeUrl(typeUrlPrefix?: string): string;
        }
    }
}
