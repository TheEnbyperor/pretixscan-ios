//
//  ConfigStore.swift
//  PretixScan
//
//  Created by Daniel Jilg on 13.03.19.
//  Copyright © 2019 rami.io. All rights reserved.
//

import Foundation

/// A protocol that defines elements that contain information about the app's configuration.
public protocol ConfigStore: AnyObject {
    // MARK: - Configuration
    /// Restore all settings to factory default and start over. Returns the app into the state at first launch.
    func factoryReset()

    // MARK: - Configured Sub Systems
    /// Creates or returns a singleton APIClient instance configured for this ConfigStore
    var apiClient: APIClient? { get }

    /// Creates or returns a singleton TicketValidator instance configured for this ConfigStore
    ///
    /// The type of TicketValidator depends on the `asyncModeEnabled` property.
    var ticketValidator: TicketValidator? { get }

    /// Returns a singleton SyncManager instance configured for this ConfigStore
    var syncManager: SyncManager { get }

    /// Creates or returns a singleton DataStore instance configured for this ConfigStore
    var dataStore: DataStore? { get }
    
    var feedbackGenerator: FeedbackGenerator { get }

    // MARK: - Welcome Screen
    /// Returns `true` if the warning screen has been accepted by the user
    var welcomeScreenIsConfirmed: Bool { get set }

    // MARK: - API Configuration
    /// The base URL for the API
    var apiBaseURL: URL? { get set }

    /// How will the tickets be validated, e.g. online or offline
    var operationMode: OperationMode { get set }

    /// If `true` the app will schedule a new sync process a few minutes after the previous one completed.
    var shouldAutoSync: Bool { get set }
    
    /// If `true` the app will download and store full order information.
    var shouldDownloadOrders: Bool { get set }
    
    /// If `true`, the app feedback generator generates audible notifications
    var shouldPlaySounds: Bool { get set }
    
    /// If `true`, the app uses the camera to scan for QR-Codes
    var useDeviceCamera: Bool { get set }
    
    /// If `true`, the app will try to use the front-facing camera of the device if it's available
    var preferFrontCamera: Bool { get set }

    /// Entry or exit
    var scanMode: String { get set }
    
    /// The last version of the app published to the server
    var publishedSoftwareVersion: String? { get set }
    
    /// If `true`, the user is allowed to use the search function
    var enableSearch: Bool {get set}

    // MARK: - Device
    /// The name that was specified for this device in the Pretix Organizer Backend
    var deviceName: String? { get set }

    /// The event organizer for this device
    var organizerSlug: String? { get set }

    /// The ID for this device as assigned by the API
    var deviceID: Int? { get set }

    /// The serial number for this device as assigned by the API
    var deviceUniqueSerial: String? { get set }
    
    /// The security profile describing the available API actions this device is allowed to perform
    var securityProfile: PXSecurityProfile {get set}
    
    /// Returns `true` if the current configuration store has been initialized with a device connection.
    var isDeviceInitialized: Bool { get }

    // MARK: - Current Event and Check-In List
    /// The currently managed event
    var event: Event? { get }
    
    var eventSettings: EventSettings? { get }

    /// All Events that are synced into a local database
    var allManagedEvents: [Event] { get }

    /// The CheckInList to scan against
    var checkInList: CheckInList? { get }
    
    /// The version of the server we're currently connected to
    var knownPretixVersion: Int? { get set }
    
    /// The id of the gate this device has been assigned to.
    var deviceKnownGateId: Int? {get set}
    
    /// The name of the gate this device has been assigned to.
    var deviceKnownGateName: String? {get set}

    /// Set both event and checkinlist
    func set(event: Event, eventSettings: EventSettings, checkInList: CheckInList)
    
    func applySecurityDefaults()
    
    func valueChanged(_ value: ConfigStoreValue?)
    
    func updateAndApplyCredentials(deviceInit: DeviceInitializationResponse)
}

extension ConfigStore {
    /// Notification that should be fired whenever a ConfigStore value changes
    var changedNotification: Notification.Name { return Notification.Name("ConfigStoreChanged") }
    var resetNotification: Notification.Name { return Notification.Name("ConfigStoreFactoryReset") }
}

/// Value Keys to be used for notifications
public enum ConfigStoreValue: String {
    /// The Organizer slug has changed
    case organizerSlug

    /// The event has changed
    case event
    
    case eventSettings

    /// The value for allManagedEvents has changed
    case allManagedEvents

    /// The checkin list has changed
    case checkInList

    /// Online/offline mode chanced
    case operationMode

    /// Should auto sync has been toggled
    case shouldAutoSync
    
    case scanMode
    
    /// Indicates if the app feedback generator generates audible notifications
    case shouldPlaySounds
    
    case shouldDownloadOrders
    
    /// Indicates if the device should use the camera to scan for QR-codes
    case useDeviceCamera
    
    case preferFrontCamera
}

public enum OperationMode: String {
    case online
    case offline
    case uic
}
