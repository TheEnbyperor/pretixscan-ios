//
//  APIClient.swift
//  PretixScan
//
//  Created by Daniel Jilg on 14.03.19.
//  Copyright © 2019 rami.io. All rights reserved.
//
// swiftlint:disable file_length

import Foundation

/// Manages requests to and responses from the Pretix REST API.
///
/// - Note: You should almost never use the APIClient directly. Instead, use an instance of `TicketValidator`, which uses
///   `APIClient`, `SyncManager` and `DataStore` in various strategies to get you the result you want.
///
/// ## Creating new API Connections
/// - Ask your user for a base URL and a device handshake token, usually via a QR code
/// - Call `init:` with a config Store
/// - Set the config store's apiBaseURL
/// - Then call initialize with a DeviceInitializationRequest that contains the handshake token to obtain an API Token
public final class APIClient {
    private var configStore: ConfigStore
    
    private let jsonEncoder = JSONEncoder.iso8601withFractionsEncoder
    private let jsonDecoder = JSONDecoder.iso8601withFractionsDecoder
    private let session = URLSession.shared
    
    /// A previously fired off search task, so we cancel it if a new task is fired before this one is completed.
    private var previousSearchTask: URLSessionDataTask?
    
    // MARK: - Initialization
    init(configStore: ConfigStore) {
        self.configStore = configStore
    }
    
    func isAllowed(request: URLRequest) -> Bool {
        return PXSecurityProfileRequestValidator.isAllowed(request, profile: self.configStore.securityProfile)
    }
}

// MARK: - Devices
public extension APIClient {
    /// Retrieve an API token from the API and save it into the attached `ConfigStore`
    func initialize(_ initializationRequest: DeviceInitializationRequest, completionHandler: @escaping (Error?) -> Void) {
        guard let baseURL = configStore.apiBaseURL else {
            let message = "Please set the APIClient's configStore.apiBaseURL property before calling this function."
            EventLogger.log(event: message, category: .configuration, level: .warning, type: .default)
            completionHandler(APIError.notConfigured(message: message))
            return
        }
        
        let url = baseURL.appendingPathComponent("/api/v1/device/initialize")
        logger.debug("API task for url '\(url.absoluteString)'")
        
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = HttpMethod.POST
        urlRequest.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // swiftlint:disable:next force_try
        urlRequest.httpBody = try! jsonEncoder.encode(initializationRequest)
        
        let task = session.dataTask(with: urlRequest) { (data, _, error) in
            guard error == nil else {
                completionHandler(error)
                return
            }
            
            guard let responseData = data else {
                completionHandler(APIError.emptyResponse)
                return
            }
            
            logger.debugRawDataAsString(responseData)
            
            let initializationResponse: DeviceInitializationResponse
            do {
                initializationResponse = try self.jsonDecoder.decode(DeviceInitializationResponse.self, from: responseData)
            } catch let jsonError {
                
                if let errorResponse = try? self.jsonDecoder.decode(DeviceInitializationResponseError.self, from: responseData),
                   let message = errorResponse.token.first {
                    completionHandler(APIError.initializationError(message: message))
                } else {
                    completionHandler(jsonError)
                }
                
                return
            }
            
            // update the app token
            let serviceURL = baseURL.absoluteString
            Keychain.set(password: initializationResponse.apiToken, account: serviceURL, service: serviceURL)
            
            // store the published version
            let pxd = PXDeviceInitialization(self.configStore)
            pxd.setPublishedVersion(initializationRequest.softwareVersion)
            
            // setup the configuration store and apply security defaults
            self.configStore.updateAndApplyCredentials(deviceInit: initializationResponse)
            
            completionHandler(nil)
        }
        
        task.resume()
    }
    
    /// Retrieves device information
    /// https://docs.pretix.eu/en/latest/api/deviceauth.html#device-information
    func getServerVersion(completionHandler: @escaping (Error?, DeviceInfoResponse?) -> Void) -> URLSessionDataTask? {
        do {
            let urlPath = try createURL(for: "/api/v1/device/info")
            var urlRequest = try createURLRequest(for: urlPath)
            urlRequest.httpMethod = HttpMethod.GET
            
            
            if !isAllowed(request: urlRequest) {
                completionHandler(APIError.notAllowed, nil)
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, _, error) in
                guard error == nil else {
                    completionHandler(error, nil)
                    return
                }
                
                guard let responseData = data else {
                    completionHandler(APIError.emptyResponse, nil)
                    return
                }
                
                logger.debugRawDataAsString(responseData)
                
                let response: DeviceInfoResponse
                do {
                    response = try self.jsonDecoder.decode(DeviceInfoResponse.self, from: responseData)
                } catch {
                    completionHandler(error, nil)
                    return
                }

                
                completionHandler(nil, response)
            }
            
            return task
            
        } catch {
            logger.error("API task error \(String(describing: error))")
            completionHandler(error, nil)
            return nil
        }
    }
    
    /// Updates the software version of the device on the server
    /// https://docs.pretix.eu/en/latest/api/deviceauth.html#updating-the-software-version
    func update(_ updateRequest: DeviceUpdateRequest, completionHandler: @escaping (Error?) -> Void) -> URLSessionDataTask? {
        
        do {
            let urlPath = try createURL(for: "/api/v1/device/update")
            var urlRequest = try createURLRequest(for: urlPath)
            urlRequest.httpMethod = HttpMethod.POST
            urlRequest.httpBody = try jsonEncoder.encode(updateRequest)
            
            
            if !isAllowed(request: urlRequest) {
                completionHandler(APIError.notAllowed)
                return nil
            }
            
            guard let serviceURL = configStore.apiBaseURL?.absoluteString else {
                completionHandler(APIError.notConfigured(message: "Attempted to make server requests without a baseURL."))
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, _, error) in
                guard error == nil else {
                    completionHandler(error)
                    return
                }
                
                guard let responseData = data else {
                    completionHandler(APIError.emptyResponse)
                    return
                }
                
                logger.debugRawDataAsString(responseData)
                
                let initializationResponse: DeviceInitializationResponse
                do {
                    initializationResponse = try self.jsonDecoder.decode(DeviceInitializationResponse.self, from: responseData)
                } catch let jsonError {
                    
                    if let errorResponse = try? self.jsonDecoder.decode(DeviceInitializationResponseError.self, from: responseData),
                       let message = errorResponse.token.first {
                        completionHandler(APIError.initializationError(message: message))
                    } else {
                        completionHandler(jsonError)
                    }
                    
                    return
                }
                
                // update the app token
                Keychain.set(password: initializationResponse.apiToken, account: serviceURL, service: serviceURL)
                self.configStore.updateAndApplyCredentials(deviceInit: initializationResponse)
                completionHandler(nil)
            }
            
            return task
            
        } catch {
            logger.error("API task error \(String(describing: error))")
            completionHandler(error)
            return nil
        }
        
    }
}

extension HTTPURLResponse {
    func find(header: String) -> String? {
        let keyValues = allHeaderFields.map { (String(describing: $0.key).lowercased(), String(describing: $0.value)) }
        if let headerValue = keyValues.filter({ $0.0 == header.lowercased() }).first {
            return headerValue.1
        }
        return nil
    }
}

// MARK: - Retrieving Items
public extension APIClient {
    
    /// Retrieve the specified model from the server and call the completion handler for each page.
    ///
    /// @see `getTask`
    func get<T: Model>(_ model: T.Type, page: Int = 1, lastUpdated: String?,
                       completionHandler: @escaping (Result<PagedList<T>, Error>) -> Void) {
        let task = getTask(model, page: page, lastUpdated: lastUpdated, completionHandler: completionHandler)
        task?.resume()
    }
    
    /// Returns a task that retrieves a detail object at the specified resource.
    ///
    /// @see `get`
    func getTask<T: Model>(_ resource: String,
                           completionHandler: @escaping (Result<T, Error>) -> Void) -> URLSessionDataTask? {
        do {
            let url = try createURL(for: "/api/v1").appendingPathComponent(resource)
            logger.debug("API task for url '\(url.absoluteString)'")
            let urlRequest = try createURLRequest(for: url)
            
            if !isAllowed(request: urlRequest) {
                completionHandler(.failure(APIError.notAllowed))
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(.failure(error))
                    return
                }
                
                guard let data = data else {
                    completionHandler(.failure(APIError.emptyResponse))
                    return
                }
                
                do {
                    let model = try self.jsonDecoder.decode(T.self, from: data)
                    completionHandler(.success(model))
                } catch {
                    return completionHandler(.failure(error))
                }
            }
            return task
        } catch {
            completionHandler(.failure(error))
            return nil
        }
    }
    
    /// Returns a task that retrieves the specified model from the server and calls the completion handler for each page, once run.
    ///
    /// @see `get`
    func getTask<T: Model>(_ model: T.Type, page: Int = 1, lastUpdated: String?, event: Event? = nil, filters: [String: String] = [:], ifModifiedSince: String? = nil,
                           completionHandler: @escaping (Result<PagedList<T>, Error>) -> Void, pageLimit: Int? = nil) -> URLSessionDataTask? {
        do {
            let organizer = try getOrganizerSlug()
            let url: URL
            if model is Event.Type {
                url = try createURL(for: "/api/v1/organizers/\(organizer)/events/")
            } else {
                let event = try event ?? getEvent()
                url = try createURL(for: "/api/v1/organizers/\(organizer)/events/\(event.slug)/\(model.stringName)/")
            }
            
            logger.debug("API task for url '\(url.absoluteString)'")
            let urlComponents = createURLComponents(url: url, page: page, lastUpdated: lastUpdated, filters: filters)
            guard let urlComponentsURL = urlComponents?.url else {
                throw APIError.couldNotCreateURL
            }
            
            var urlRequest = try createURLRequest(for: urlComponentsURL)
            
            if (ifModifiedSince != nil) {
                urlRequest.addValue(ifModifiedSince!, forHTTPHeaderField: "If-Modified-Since")
            }
            
            if !isAllowed(request: urlRequest) {
                completionHandler(.failure(APIError.notAllowed))
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(.failure(error))
                    return
                }
                
                guard let data = data else {
                    completionHandler(.failure(APIError.emptyResponse))
                    return
                }
                
                do {
                    var pagedList = try self.jsonDecoder.decode(PagedList<T>.self, from: data)
                    pagedList.generatedAt = (response as? HTTPURLResponse)?.find(header: "X-Page-Generated")
                    pagedList.lastModified = (response as? HTTPURLResponse)?.find(header: "Last-Modified")
                    
                    // Check if there are more pages to load
                    if (pageLimit != nil && page >= pageLimit!) {
                        pagedList.next = nil
                    }
                    
                    completionHandler(.success(pagedList))
                    
                    if pagedList.next != nil {
                        self.getTask(model, page: page+1, lastUpdated: lastUpdated, event: event,
                                     filters: filters, completionHandler: completionHandler,
                                     pageLimit: pageLimit)?.resume()
                    }
                } catch {
                    return completionHandler(.failure(error))
                }
                
            }
            return task
        } catch {
            completionHandler(.failure(error))
            return nil
        }
    }
    
    private func createURLComponents(url: URL, page: Int, lastUpdated: String?, filters: [String: String] = [:]) -> URLComponents? {
        var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)
        var queryItems = [URLQueryItem]()
        queryItems.append(URLQueryItem(name: "page", value: "\(page)"))
        if lastUpdated != nil {
            queryItems.append(URLQueryItem(name: "modified_since", value: lastUpdated))
        }
        
        let isFullFetch = lastUpdated == nil
        if isFullFetch {
            queryItems.append(URLQueryItem(name: "ordering", value: "datetime"))
        } else {
            queryItems.append(URLQueryItem(name: "ordering", value: "-last_modified"))
        }
        
        for filter in filters {
            queryItems.append(URLQueryItem(name: filter.key, value: filter.value))
        }
        urlComponents?.queryItems = queryItems
        
        // Fix a missing feature in URLComponents where the "+" is not encoded correctly
        // https://www.djackson.org/why-we-do-not-use-urlcomponents/
        let percentEncodedURLQuery = urlComponents!.percentEncodedQuery!
        // manually encode + into percent encoding
            .replacingOccurrences(of: "+", with: "%2B")
        // optional, probably unnecessary: convert percent-encoded spaces into +
            .replacingOccurrences(of: "%20", with: "+")
        urlComponents!.percentEncodedQuery = percentEncodedURLQuery
        
        return urlComponents
    }
}

// MARK: - Events
public extension APIClient {
    /// Returns a list of all events within a given organizer the authenticated user/token has access to.
    func getEvents(completionHandler: @escaping ([Event]?, Error?) -> Void) {
        var results = [Event]()
        
        let eightHoursAgo = Calendar.current.date(byAdding: .hour, value: -8, to: Date())!
        let endsAfter = Formatter.iso8601.string(from: eightHoursAgo)
        let task = getTask(Event.self, lastUpdated: nil, filters: ["ends_after": endsAfter, "ordering": "date_from"], completionHandler:  { result in
            switch result {
            case .failure(let error):
                completionHandler(nil, error)
            case .success(let resultList):
                results += resultList.results
                if resultList.next == nil {
                    // Last Page
                    let task = self.getTask(Event.self, lastUpdated: nil, filters: ["has_subevents": "true"]) { result in
                        switch result {
                        case .failure(let error):
                            completionHandler(nil, error)
                        case .success(let resultList):
                            results += resultList.results
                            if resultList.next == nil {
                                // Last Page
                                completionHandler(results, nil)
                            }
                        }
                    }
                    task?.resume()
                }
            }
        }, pageLimit: 5)
        task?.resume()
    }
    
    func getEventSettings(event: Event, completionHandler: @escaping (EventSettings?, Error?) -> Void) {
        do {
            let organizer = try getOrganizerSlug()
            let task = getTask("organizers/\(organizer)/events/\(event.slug)/settings/", completionHandler: { (result: Result<EventSettings, Error>) in
                switch result {
                case .failure(let error):
                    completionHandler(nil, error)
                case .success(let eventSettings):
                    completionHandler(eventSettings, nil)
                }
            })
            task?.resume()
        } catch {
            completionHandler(nil, error)
        }
    }
    
    /// Returns a list of all subevents in the completionHandler
    func getSubEvents(event: Event, completionHandler: @escaping ([SubEvent]?, Error?) -> Void) {
        var results = [SubEvent]()
        
        let dayAgo = Calendar.current.date(byAdding: .hour, value: -8, to: Date())!
        let endsAfter = Formatter.iso8601.string(from: dayAgo)
        
        let task = getTask(SubEvent.self, lastUpdated: nil, event: event, filters: ["ends_after": endsAfter, "ordering": "date_from"], completionHandler:  { result in
            switch result {
            case .failure(let error):
                completionHandler(nil, error)
            case .success(let resultList):
                results += resultList.results
                if resultList.next == nil {
                    // Last Page
                    completionHandler(results, nil)
                }
            }
        }, pageLimit: 5)
        task?.resume()
    }
}

// MARK: - Check In Lists
public extension APIClient {
    /// Returns a list of all check-in lists within a given event.
    func getCheckinLists(event: Event, completionHandler: @escaping ([CheckInList]?, Error?) -> Void) {
        var results = [CheckInList]()
        
        let task = getTask(CheckInList.self, lastUpdated: nil, event: event) { result in
            switch result {
            case .failure(let error):
                completionHandler(nil, error)
            case .success(let resultList):
                results += resultList.results
                if resultList.next == nil {
                    // Last Page
                    completionHandler(results, nil)
                }
            }
        }
        task?.resume()
    }
    
    /// Search all OrderPositions within a CheckInList
    ///
    /// Note: Firing off a search query will invalidate all previous queries
    func getSearchResults(query: String, completionHandler: @escaping ([OrderPosition]?, Error?) -> Void) {
        do {
            let organizer = try getOrganizerSlug()
            let event = try getEvent()
            let checkInList = try getCheckInList()
            let url = try createURL(for: "/api/v1/organizers/\(organizer)/events/\(event.slug)" +
                                       "/checkinlists/\(checkInList.identifier)/positions/")
            
            var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)
            urlComponents?.queryItems = [
                URLQueryItem(name: "search", value: query),
                URLQueryItem(name: "ignore_status", value: "true")
            ]
            guard let urlComponentsURL = urlComponents?.url else {
                throw APIError.couldNotCreateURL
            }
            let urlRequest = try createURLRequest(for: urlComponentsURL)
            
            if !isAllowed(request: urlRequest) {
                completionHandler(nil, APIError.notAllowed)
                return
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    if let error = error as NSError? {
                        if error.code == NSURLErrorCancelled {
                            
                            completionHandler(nil, nil)
                            return
                        }
                    }
                    
                    completionHandler(nil, error)
                    return
                }
                
                let pagedListResult: (list: PagedList<OrderPosition>?, error: Error?) = self.pagedList(from: data!)
                completionHandler(pagedListResult.list?.results, pagedListResult.error)
            }
            previousSearchTask?.cancel()
            
            // Wait a short while before firing off the request to see if there are
            // further requests coming (i.e. the user is still typing)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                task.resume()
            }
            
            previousSearchTask = task
            
        } catch {
            completionHandler(nil, error)
        }
    }
    
    /// Check in an attendee, identified by their secret code, into the currently configured CheckInList
    ///
    /// - See `RedemptionResponse` for the response returned in the completion handler.
    func redeem(secret: String, force: Bool, ignoreUnpaid: Bool, answers: [Answer]?, as type: String,
                completionHandler: @escaping (RedemptionResponse?, Error?) -> Void) {
        Task {
            let answersWithFiles = await uploadAttachments(answers: answers)
            if let task = redeemTask(secret: secret, force: force, ignoreUnpaid: ignoreUnpaid, answers: answersWithFiles,
                                     as: type,
                                     completionHandler: completionHandler) {
                task.resume()
            }
        }
    }
    
    /// Create a paused task to check in an attendee, identified by their secret code, into the currently configured CheckInList
    func redeemTask(secret: String, force: Bool, ignoreUnpaid: Bool, date: Date? = nil, eventSlug: String? = nil,
                    checkInListIdentifier: Identifier? = nil, answers: [Answer]? = nil, as type: String,
                    completionHandler: @escaping (RedemptionResponse?, Error?) -> Void) -> URLSessionDataTask? {
        
        let redemptionRequest = RedemptionRequest(
            questionsSupported: true,
            date: date, force: force, ignoreUnpaid: ignoreUnpaid,
            nonce: NonceGenerator.nonce(), answers: answers, type: type)
        
        return createCheckInTask(secret: secret, redemptionRequest: redemptionRequest, eventSlug: eventSlug,
                          checkInListIdentifier: checkInListIdentifier, completionHandler: completionHandler)
    }
    
    func uploadAttachments(answers: [String: String]) async -> [String: String] {
        var answersWithFiles = answers
        for (questionId, answer) in answersWithFiles {
            if PXTemporaryFile.isTemporaryFilePath(answer) {
                logger.debug("Uploading file for question \(questionId).")
                if let file = try? await uploadAttachment(file: PXTemporaryFile.removePathPrefix(answer)) {
                    answersWithFiles[questionId] = file.id
                }
            }
        }
        return answersWithFiles
    }
    
    func uploadAttachments(answers: [Answer]?) async -> [Answer]? {
        guard var answersWithFiles = answers else {
            return nil
        }
        for (ix, answer) in answersWithFiles.enumerated() {
            if let fileUrl = answer.fileUrl {
                logger.debug("Uploading file for question \(answer.question.id).")
                if let file = try? await uploadAttachment(file: PXTemporaryFile(contentURL: fileUrl, name: fileUrl.lastPathComponent)) {
                    logger.debug("File for question \(answer.question.id) uploaded as \(file.id).")
                    answersWithFiles[ix].fileUrl = nil
                    answersWithFiles[ix].answer = file.id
                }
            }
        }
        return answersWithFiles
    }
    
    private func uploadAttachment(file: PXTemporaryFile) async throws -> PXUploadedFile {
        return try await withCheckedThrowingContinuation { continuation in
            uploadFile(file: file, completionHandler: { result in
                continuation.resume(with: result)
            })
        }
    }
    
    private func uploadFile(file: PXTemporaryFile, completionHandler: @escaping (Result<PXUploadedFile, Error>) -> ()) {
        let task = uploadFileTask(file: file, completionHandler: completionHandler)
        task?.resume()
    }
    
    private func uploadFileTask(file: PXTemporaryFile, completionHandler: @escaping (Result<PXUploadedFile, Error>) -> ()) -> URLSessionDataTask? {
        
        guard let mimeType = file.contentURL.mimeType() else {
            logger.error("File for upload at path '\(file.contentURL)' has unknown mime type.")
            completionHandler(.failure(APIError.unknownFileType))
            return nil
        }
        
        guard let fileData = try? Data(contentsOf: file.contentURL), !fileData.isEmpty else {
            logger.error("Find file for upload at path '\(file.contentURL)' is empty.")
            completionHandler(.failure(APIError.fileNotFound))
            return nil
        }
        
        do {
            let urlPath = try createURL(for: "/api/v1/upload")
            var urlRequest = try createURLRequestForAnyContent(for: urlPath)
            urlRequest.addValue(mimeType, forHTTPHeaderField: "Content-Type")
            urlRequest.addValue("attachment; filename=\"\(file.contentURL.lastPathComponent)\"", forHTTPHeaderField: "Content-Disposition")
            urlRequest.addValue("\(fileData.count)", forHTTPHeaderField: "Content-Length")
            
            urlRequest.httpMethod = HttpMethod.POST
            urlRequest.httpBody = fileData
            
            if !isAllowed(request: urlRequest) {
                completionHandler(.failure(APIError.notAllowed))
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(.failure(error))
                } else {
                    do {
                        let uploadedFile = try self.jsonDecoder.decode(PXUploadedFile.self, from: data!)
                        completionHandler(.success(uploadedFile))
                    } catch {
                        logger.error("Failed to decode server response for uploaded file: \(String(describing: error))")
                        EventLogger.log(event: "Failed to decode server response for uploaded file: \(String(describing: error))", category: .network, level: .error, type: .error)
                        completionHandler(.failure(APIError.badRequest))
                    }
                }
            }
            return task
            
        } catch {
            logger.error("Failed to upload file: \(String(describing: error))")
            completionHandler(.failure(error))
            return nil
        }
    }
    
    /// Create a paused task to check in an attendee, identified by their secret code, into the currently configured CheckInList
    func failedCheckInTask(_ failedCheckIn: FailedCheckIn,
                           completionHandler: @escaping (Error?) -> Void) -> URLSessionDataTask? {
        do {
            let organizer = try getOrganizerSlug()
            let urlPath = try createURL(for: "/api/v1/organizers/\(organizer)/events/\(failedCheckIn.eventSlug)" +
                                           "/checkinlists/\(failedCheckIn.checkInListIdentifier)/failed_checkins/")
            var urlRequest = try createURLRequest(for: urlPath)
            urlRequest.httpMethod = HttpMethod.POST
            urlRequest.httpBody = try jsonEncoder.encode(FailedCheckInRequest(failedCheckIn))
            
            if !isAllowed(request: urlRequest) {
                completionHandler(APIError.notAllowed)
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(error)
                } else {
                    completionHandler(nil)
                }
            }
            return task
        } catch {
            completionHandler(error)
            return nil
        }
    }
    
    
    func createCheckInTask(secret: String, redemptionRequest: RedemptionRequest, eventSlug: String? = nil,
                    checkInListIdentifier: Identifier? = nil,
                    completionHandler: @escaping (RedemptionResponse?, Error?) -> Void) -> URLSessionDataTask? {
        
        if configStore.knownPretixVersion ?? 0 >= 40120001001 {
            return checkInTask(secret: secret, redemptionRequest: redemptionRequest, completionHandler: completionHandler)
        } else {
            return redeemPositionTask(secret: secret, redemptionRequest: redemptionRequest, eventSlug: eventSlug, checkInListIdentifier: checkInListIdentifier, completionHandler: completionHandler)
        }
    }
    
    private func createRedeemURL(organizer: String) throws -> URL {
        let url = try createURL(for: "/api/v1/organizers/\(organizer)/checkinrpc/redeem/")
        return try addExpandQuery(url)
    }
    
    private func addExpandQuery(_ url: URL) throws -> URL {
        var url = url
        if #available(iOS 16.0, *) {
            url.append(queryItems: [URLQueryItem(name: "expand", value: "answers.question")])
        } else {
            // Fallback on earlier versions
            var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false)
            urlComponents?.queryItems = [URLQueryItem(name: "expand", value: "answers.question")]
            guard let urlComponentsURL = urlComponents?.url else {
                throw APIError.couldNotCreateURL
            }
            url = urlComponentsURL
        }
        return url
    }
    
    /// Create a paused task to check in an attendee, identified by their secret code, into the currently configured CheckInList
    private func checkInTask(secret: String, redemptionRequest: RedemptionRequest, checkInListIdentifier: Identifier? = nil,
                    completionHandler: @escaping (RedemptionResponse?, Error?) -> Void) -> URLSessionDataTask? {
        do {
            let organizer = try getOrganizerSlug()
            let checkInListId = try checkInListIdentifier ?? (try getCheckInList()).identifier
            let request = CheckInRequest(list: checkInListId, secret: secret, redemptionRequest: redemptionRequest)
            
            let url = try createRedeemURL(organizer: organizer)
            var urlRequest = try createURLRequest(for: url)
            urlRequest.httpMethod = HttpMethod.POST
            urlRequest.httpBody = try jsonEncoder.encode(request)
            
            if !isAllowed(request: urlRequest) {
                completionHandler(nil, APIError.notAllowed)
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
#if DEBUG
                if let data = data {
                    print("response error", String(data: data, encoding: .utf8))
                }
#endif
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(nil, error)
                    return
                }
                
                do {
                    let redemptionResponse = try self.jsonDecoder.decode(RedemptionResponse.self, from: data!)
                    completionHandler(redemptionResponse, nil)
                } catch let jsonError {
                    completionHandler(nil, jsonError)
                    return
                }
            }
            return task
        } catch {
            completionHandler(nil, error)
            return nil
        }
    }
    
    
    /// Create a paused task to check in an attendee, identified by their secret code, into the currently configured CheckInList
    @available(*, deprecated, renamed: "checkInTask")
    private func redeemPositionTask(secret: String, redemptionRequest: RedemptionRequest, eventSlug: String? = nil,
                    checkInListIdentifier: Identifier? = nil,
                    completionHandler: @escaping (RedemptionResponse?, Error?) -> Void) -> URLSessionDataTask? {
        do {
            let organizer = try getOrganizerSlug()
            let event = try getEvent()
            let checkInList = try getCheckInList()
            let urlPath = try createURL(for: "/api/v1/organizers/\(organizer)/events/\(eventSlug ?? event.slug)" +
                                           "/checkinlists/\(checkInListIdentifier ?? checkInList.identifier)/positions/\(secret)/redeem/")
            var urlRequest = try createURLRequest(for: urlPath)
            urlRequest.httpMethod = HttpMethod.POST
            urlRequest.httpBody = try jsonEncoder.encode(redemptionRequest)
            
            if !isAllowed(request: urlRequest) {
                completionHandler(nil, APIError.notAllowed)
                return nil
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(nil, error)
                    return
                }
                
                do {
                    let redemptionResponse = try self.jsonDecoder.decode(RedemptionResponse.self, from: data!)
                    completionHandler(redemptionResponse, nil)
                } catch let jsonError {
                    completionHandler(nil, jsonError)
                    return
                }
            }
            return task
        } catch {
            completionHandler(nil, error)
            return nil
        }
    }
    
    /// Get Status information for the current CheckInList
    func getCheckInListStatus(completionHandler: @escaping (CheckInListStatus?, Error?) -> Void) {
        do {
            let organizer = try getOrganizerSlug()
            let event = try getEvent()
            let checkInList = try getCheckInList()
            let urlPath = try createURL(for: "/api/v1/organizers/\(organizer)/events/\(event.slug)" +
                                           "/checkinlists/\(checkInList.identifier)/status/")
            let urlRequest = try createURLRequest(for: urlPath)
            
            if !isAllowed(request: urlRequest) {
                completionHandler(nil, APIError.notAllowed)
                return
            }
            
            let task = session.dataTask(with: urlRequest) { (data, response, error) in
                if let error = self.checkResponse(data: data, response: response, error: error) {
                    completionHandler(nil, error)
                    return
                }
                
                do {
                    let checkInListStatus = try self.jsonDecoder.decode(CheckInListStatus.self, from: data ?? Data())
                    completionHandler(checkInListStatus, nil)
                } catch let jsonError {
                    completionHandler (nil, jsonError)
                }
            }
            task.resume()
        } catch {
            completionHandler(nil, error)
        }
    }
}

// MARK: - Accessing Properties
extension APIClient {
    func getOrganizerSlug() throws -> String {
        guard let organizer = configStore.organizerSlug else {
            throw APIError.notConfigured(message:
                                            "APIClient's configStore.organizerSlug property must be set before calling this function."
            )
        }
        
        return organizer
    }
    
    func getEvent() throws -> Event {
        guard let event = configStore.event else {
            throw APIError.notConfigured(message: "APIClient's configStore.event property must be set before calling this function.")
        }
        
        return event
    }
    
    func getCheckInList() throws -> CheckInList {
        guard let checkInList = configStore.checkInList else {
            throw APIError.notConfigured(message: "APIClient's configStore.checkInList property must be set before calling this function.")
        }
        
        return checkInList
    }
}

// MARK: - Creating Requests
private extension APIClient {
    func createURLRequest(for pathComponent: String) throws -> URLRequest {
        let url = try createURL(for: pathComponent)
        let urlRequest = try createURLRequest(for: url)
        return urlRequest
    }
    
    func createURL(for pathComponent: String) throws -> URL {
        guard let baseURL = configStore.apiBaseURL else {
            throw APIError.notConfigured(message: "APIClient's configStore.apiBaseURL property must be set before calling this function.")
        }
        
        return baseURL.appendingPathComponent(pathComponent)
    }
    
    func createURLRequest(for url: URL) throws -> URLRequest {
        var urlRequest = try createURLRequestForAnyContent(for: url)
        urlRequest.addValue("application/json", forHTTPHeaderField: "Content-Type")
        return urlRequest
    }
    
    func createURLRequestForAnyContent(for url: URL) throws -> URLRequest {
        guard let serviceURL = configStore.apiBaseURL?.absoluteString, let apiToken = Keychain.get(account: serviceURL, service: serviceURL) else {
            throw APIError.notConfigured(message: "Attempted to make server requests without a token present.")
        }
        
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = HttpMethod.GET
        urlRequest.addValue("Device \(apiToken)", forHTTPHeaderField: "Authorization")
        urlRequest.httpBody = nil
        urlRequest.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return urlRequest
    }
    
    func checkResponse(data: Data?, response: URLResponse?, error: Error?) -> Error? {
        guard error == nil else {
            return error
        }
        
        guard data != nil else {
            return APIError.emptyResponse
        }
        
        guard let httpURLResponse = response as? HTTPURLResponse else {
            return APIError.nonHTTPResponse
        }
        
        guard [200, 201, 400].contains(httpURLResponse.statusCode) else {
            // check for a server error to show to the user
            if let data = data,
               let serverError = try? jsonDecoder.decode(ServerErrorMessage.self, from: data),
               let managedErrorCode = APIError(from: serverError) {
                return managedErrorCode
            }
            
            switch httpURLResponse.statusCode {
            case 304:
                return APIError.unchanged
            case 401:
                return APIError.unauthorized
            case 403:
                return APIError.forbidden
            case 404:
                return APIError.notFound
            case 429:
                guard let retryAfter = httpURLResponse.find(header: "Retry-After"), let retryAfterSelconds = Int(retryAfter) else {
                    return APIError.unknownStatusCode(statusCode: httpURLResponse.statusCode)
                }
                return APIError.retryAfter(seconds: retryAfterSelconds)
            default:
                return APIError.unknownStatusCode(statusCode: httpURLResponse.statusCode)
            }
        }
        
        return nil
    }
    
    func pagedList<T: Codable>(from data: Data) -> (list: PagedList<T>?, error: Error?) {
        do {
            return (try self.jsonDecoder.decode(PagedList<T>.self, from: data), nil)
        } catch let jsonError {
            return (nil, jsonError)
        }
    }
}

