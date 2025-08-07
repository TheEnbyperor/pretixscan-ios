//
//  UICTicketValidator.swift
//  pretixSCAN
//
//  Created by Q Misell on 16.07.25.
//

import Foundation

public class UICTicketValidator: OfflineTicketValidator {
    private let uic: pretix_uic?
    private let configStore: ConfigStore

    public override init(configStore: ConfigStore) {
        guard let publicKeyStr = configStore.eventSettings?.uic_public_key else {
            logger.error("UIC: no public key available for verifying")
            self.uic = nil
            self.configStore = configStore
            super.init(configStore: configStore)
            return
        }
        var uicInstance: pretix_uic? = nil
        publicKeyStr.withCString { publicKeyPtr in
            var uicConfig = pretix_uic_config(
                public_key: publicKeyPtr,
                security_provider_rics: 0,
                security_provider_ia5: nil,
                key_id: 0,
                key_id_ia5: nil
            )
            
            var securityProviderIA5: [CChar]? = nil
            var keyIdIA5: [CChar]? = nil
            
            switch configStore.eventSettings?.uic_security_provider {
            case .int(let id):
                uicConfig.security_provider_rics = UInt32(id)
            case .ia5(let id):
                securityProviderIA5 = id.cString(using: .utf8)
                uicConfig.security_provider_ia5 = UnsafePointer(securityProviderIA5!)!
            case nil:
                logger.error("UIC: Security Provider not configured")
                return
            }
            
            switch configStore.eventSettings?.uic_key_id {
            case .int(let id):
                uicConfig.key_id = UInt32(id)
            case .ia5(let id):
                keyIdIA5 = id.cString(using: .utf8)
                uicConfig.key_id_ia5 = UnsafePointer(keyIdIA5!)!
            case nil:
                logger.error("UIC: Key ID not configured")
                return
            }
            
            guard let uic = (withUnsafePointer(to: &uicConfig) { ptr in
                pretix_uic_new(ptr)
            }) else {
                print("UIC: failed to initalise library")
                return
            }
            uicInstance = uic
        }
        self.uic = uicInstance
        self.configStore = configStore
        super.init(configStore: configStore)
    }
    
    deinit {
        pretix_uic_free(self.uic)
    }
    
    public override func redeem(configuration: TicketStatusConfiguration, as type: String) async throws -> RedemptionResponse? {
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<RedemptionResponse?, Error>) in
            guard let event = configStore.event else {
                continuation.resume(throwing: APIError.notConfigured(message: "No Event is set"))
                return
            }
            
            guard let checkInList = configStore.checkInList else {
                continuation.resume(throwing: APIError.notConfigured(message: "No CheckInList is set"))
                return
            }
            
            let nowDate = Date()
            
            if self.uic == nil {
                continuation.resume(returning: RedemptionResponse.invalid)
                return
            }
            
            let checkInListLimitProducts: [Int64] = checkInList.limitProducts?.map { Int64($0) } ?? []
            let (result, uniqueId) = event.slug.withCString({ eSlug in
                checkInListLimitProducts.withUnsafeBufferPointer({ (cArray: UnsafeBufferPointer<Int64>) in
                    var scanConfig = pretix_uic_scan_conf(
                        is_exit: type == "exit",
                        event_slug: eSlug,
                        checkin_list_all_products: checkInList.allProducts,
                        checkin_list_limit_products_count: checkInList.limitProducts?.count ?? 0,
                        checkin_list_limit_products: cArray.baseAddress,
                        checkin_list_has_sub_event_id: checkInList.subEvent != nil,
                        checkin_list_sub_event_id: Int64(checkInList.subEvent ?? 0),
                    )
                    
                    return configuration.secret.withUnsafeBytes({ (data: UnsafeRawBufferPointer) in
                        let r = (withUnsafePointer(to: &scanConfig) { ptr in
                            pretix_uic_scan(uic, data.baseAddress, Int32(data.count), ptr)!
                        })
                        let result = (r.pointee, r.pointee.unique_id != nil ? String(cString: r.pointee.unique_id) : "")
                        pretix_uic_scan_free(r)
                        return result
                    })
                })
            })
            
            logger.debug("UIC: scan result=\(String(describing: result))")
            logger.debug("UIC: unique ID=\(uniqueId)")
            
            var response: RedemptionResponse = RedemptionResponse.invalid
            let rawBarcode = configuration.secret.base64EncodedString()
            
            switch result.result {
            case PRETIX_UIC_SCAN_INVALID:
                response = RedemptionResponse.invalid
                if let failedCheckIn = FailedCheckIn(response: response, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                    configStore.dataStore?.store(failedCheckIn, for: event)
                }
            case PRETIX_UIC_SCAN_INVALID_TIME:
                response = RedemptionResponse.invalidTime
                if let failedCheckIn = FailedCheckIn(response: RedemptionResponse.invalidTime, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                    configStore.dataStore?.store(failedCheckIn, for: event)
                }
            case PRETIX_UIC_SCAN_INVALID_PRODUCT:
                response = RedemptionResponse.product
                if let failedCheckIn = FailedCheckIn(response: RedemptionResponse.product, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                    configStore.dataStore?.store(failedCheckIn, for: event)
                }
            case PRETIX_UIC_SCAN_INVALID_SUB_EVENT:
                response = RedemptionResponse.invalid
                if let failedCheckIn = FailedCheckIn(response: RedemptionResponse.product, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                    configStore.dataStore?.store(failedCheckIn, for: event)
                }
            case PRETIX_UIC_SCAN_VALID:
                let dataStoreResponse = configStore.dataStore?.redeem(secret: uniqueId, force: configuration.force, ignoreUnpaid: configuration.ignoreUnpaid, answers: configuration.answers,
                                                             in: event, as: type, in: checkInList)
                
                guard var dataStoreResponse = dataStoreResponse else {
                    if let revokedKeys = try? configStore.dataStore?.getRevokedKeys(for: event).get(), revokedKeys.contains(where: {$0.secret == uniqueId}) {
                        if let failedCheckIn = FailedCheckIn(response: RedemptionResponse.revoked, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                            configStore.dataStore?.store(failedCheckIn, for: event)
                        }
                        continuation.resume(returning: RedemptionResponse.revoked)
                        return
                    }
                    
                    if let blockedKeys = try? configStore.dataStore?.getBlockedKeys(for: event).get(), blockedKeys.contains(where: {$0.secret == uniqueId && $0.blocked}) {
                        if let failedCheckIn = FailedCheckIn(response: RedemptionResponse.blocked, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                            configStore.dataStore?.store(failedCheckIn, for: event)
                        }
                        continuation.resume(returning: RedemptionResponse.blocked)
                        return
                    }
                    
                    guard let item = configStore.dataStore?.getItem(by: Identifier(result.item_id), in: event) else {
                        response = RedemptionResponse.product
                        if let failedCheckIn = FailedCheckIn(response: response, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                            configStore.dataStore?.store(failedCheckIn, for: event)
                        }
                        continuation.resume(returning: response)
                        return
                    }
                    
                    let variation = item.variations.first(where: {$0.identifier == result.variation_id})
                    
                    if type == "exit" {
                        let request = RedemptionRequest(date: nowDate, force: true, ignoreUnpaid: configuration.ignoreUnpaid, nonce: NonceGenerator.nonce(), answers: configuration.answers, type: type)
                        let queuedRequest = QueuedRedemptionRequest(redemptionRequest: request, eventSlug: event.slug, checkInListIdentifier: checkInList.identifier, secret: uniqueId)
                        configStore.dataStore?.store(queuedRequest, for: event)
                        response = RedemptionResponse.redeemed(item, variation: variation)
                    }
                    
                    let subEvent = ((try? configStore.dataStore?.getSubEvents(for: event).get()) ?? []).first
                    switch TicketJsonLogicChecker(list: checkInList, dataStore: configStore.dataStore!, event: event, subEvent: subEvent, date: nowDate).redeem(ticket: .init(secret: uniqueId, eventSlug: event.slug, item: Identifier(result.item_id), variation: Identifier(result.variation_id))) {
                    case .success():
                        switch TicketEntryAnswersChecker(item: item, dataStore: configStore.dataStore!).redeem(event: event, answers: configuration.answers) {
                        case .success:
                            switch TicketMultiEntryChecker(list: checkInList, dataStore: configStore.dataStore!).redeem(secret: uniqueId, event: event) {
                            case .success():
                                let request = RedemptionRequest(date: nowDate, force: true, ignoreUnpaid: configuration.ignoreUnpaid, nonce: NonceGenerator.nonce(), answers: configuration.answers, type: type)
                                let queuedRequest = QueuedRedemptionRequest(redemptionRequest: request, eventSlug: event.slug, checkInListIdentifier: checkInList.identifier, secret: uniqueId)
                                configStore.dataStore?.store(queuedRequest, for: event)
                                response = RedemptionResponse.redeemed(item, variation: variation)
                            case .failure(let check):
                                logger.debug("TicketMultiEntryChecker failed: \(String(describing: check))")
                                switch check {
                                case .alreadyRedeemed:
                                    response = RedemptionResponse.alreadyRedeemed
                                    if let failedCheckIn = FailedCheckIn(response: response, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                                        configStore.dataStore?.store(failedCheckIn, for: event)
                                    }
                                case .unknownError:
                                    continuation.resume(throwing: APIError.notFound)
                                }
                            }
                        case .failure(let check):
                            logger.debug("TicketEntryAnswersChecker failed: \(String(describing: check))")
                            switch check {
                            case .incomplete(questions: let questions):
                                response = RedemptionResponse(incompleteQuestions: questions, configuration.answers)
                                if let failedCheckIn = FailedCheckIn(response: response, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                                    configStore.dataStore?.store(failedCheckIn, for: event)
                                }
                            case .unknownError:
                                continuation.resume(throwing: APIError.notFound)
                            }
                        }
                    case .failure(let rulesError):
                        logger.debug("TicketJsonLogicChecker failed: \(String(describing: rulesError))")
                        switch rulesError {
                        case .rules:
                            response = RedemptionResponse.rules
                            if let failedCheckIn = FailedCheckIn(response: response, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                                configStore.dataStore?.store(failedCheckIn, for: event)
                            }
                        case .parsingError(reason: _):
                            response = RedemptionResponse.rules
                            if let failedCheckIn = FailedCheckIn(response: response, error: nil, event.slug, checkInList.identifier, type, rawBarcode, event) {
                                configStore.dataStore?.store(failedCheckIn, for: event)
                            }
                        }
                    }
                    
                    continuation.resume(returning: response)
                    return
                }
                
                guard var position = dataStoreResponse.position else {
                    continuation.resume(returning: dataStoreResponse)
                    return
                }
                guard let checkInList = self.configStore.checkInList else {
                    continuation.resume(returning: dataStoreResponse)
                    return
                }
                guard let dataStore = configStore.dataStore else {
                    continuation.resume(returning: dataStoreResponse)
                    return
                }
                
                if let event = configStore.event {
                    position = position.adding(order: dataStore.getOrder(by: position.orderCode, in: event))
                        .adding(item: dataStore.getItem(by: position.itemIdentifier, in: event))
                        .adding(checkIns: dataStore.getCheckIns(for: position, in: configStore.checkInList, in: event))
                        .adding(answers: dataStoreResponse.answers)
                    dataStoreResponse.position = position
                    
                    dataStoreResponse.lastCheckIn = position.checkins.filter {
                        $0.listID == checkInList.identifier
                    }.first
                }
                
                
                continuation.resume(returning: dataStoreResponse)
                configStore.syncManager.beginSyncingIfAutoSync()
                return
            default:
                response = RedemptionResponse.invalid
            }
            
            continuation.resume(returning: response)
        }
    }
}

