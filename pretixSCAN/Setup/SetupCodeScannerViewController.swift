//
//  SetupCodeScannerViewController.swift
//  PretixScan
//
//  Created by Daniel Jilg on 02.04.19.
//  Copyright © 2019 rami.io. All rights reserved.
//

import UIKit

protocol SetupScannerViewControllerDelegate: AnyObject {
    func initialize(token: String, url: URL)
}

class SetupCodeScannerViewController: ScannerViewController {
    weak var delegate: SetupScannerViewControllerDelegate?

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        shouldScan = true
    }

    override func found(code: Data) {
        do {
            let handshake = try JSONDecoder.iso8601withFractionsDecoder.decode(Handshake.self, from: code)
            delegate?.initialize(token: handshake.token, url: handshake.url)
            self.shouldScan = false
        } catch let error {
            self.presentErrorAlert(ifError: error)
        }
    }
}
