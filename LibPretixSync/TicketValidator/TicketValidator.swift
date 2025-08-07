//
//  TicketValidator.swift
//  PretixScan
//
//  Created by Daniel Jilg on 19.03.19.
//  Copyright © 2019 rami.io. All rights reserved.
//

import Foundation

/// Exposes methods to check the validity of tickets and show event status.
public protocol TicketValidator {
    /// Retrieve Statistics for the currently selected CheckInList
    func getCheckInListStatus(completionHandler: @escaping (CheckInListStatus?, Error?) -> Void)

    /// Questions that should be answered for the current item
    func getQuestions(for item: Item, event: Event, completionHandler: @escaping ([Question]?, Error?) -> Void)

    // MARK: - Search
    /// Search all OrderPositions within a CheckInList
    func search(query: String, _ locale: Locale) async throws -> [SearchResult]

    // MARK: - Redemption
    /// Attempt to check in the ticket
    func redeem(configuration: TicketStatusConfiguration, as type: String) async throws -> RedemptionResponse?
    
    /// Indicates if the ticket validator instance uses online validation or local DataStore state validation.
    var isOnline: Bool {get}
}
