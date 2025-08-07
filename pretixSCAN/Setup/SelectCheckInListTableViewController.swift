//
//  SelectCheckInListTableViewController.swift
//  PretixScan
//
//  Created by Daniel Jilg on 18.03.19.
//  Copyright © 2019 rami.io. All rights reserved.
//

import UIKit

class SelectCheckInListTableViewController: UITableViewController, Configurable {
    var configStore: ConfigStore?
    var event: Event?
    var eventSettings: EventSettings?
    var subEvent: SubEvent?

    private var isLoading = true {
        didSet {
            DispatchQueue.main.async {
                if self.isLoading {
                    self.tableView.refreshControl?.beginRefreshing()
                } else {
                    self.tableView.refreshControl?.endRefreshing()
                }
                self.tableView.reloadData()
            }
        }
    }

    private var checkInLists: [CheckInList]?

    // MARK: - View Lifecycle
    override func viewDidLoad() {
        super.viewDidLoad()
        title = Localization.SelectCheckInListTableViewController.Title
        refreshControl?.addTarget(self, action: #selector(updateView), for: .valueChanged)
    }

    override func viewWillAppear(_ animated: Bool) {
        updateView()
    }

    @objc private func updateView() {
        isLoading = true
        guard let event = event else { return }

        configStore?.apiClient?.getCheckinLists(event: event) { (checkInLists, error) in
            self.presentErrorAlert(ifError: error)

            if let subEvent = self.subEvent {
                let filteredCheckInLists = checkInLists?.filter {
                    $0.subEvent == subEvent.identifier || $0.subEvent == nil
                }
                self.checkInLists = filteredCheckInLists
            } else {
                self.checkInLists = checkInLists
            }

            self.isLoading = false
        }
    }

    // MARK: - Table view data source
    private static let reuseIdentifier = "SelectCheckInListTableViewControllerCell"
    override func numberOfSections(in tableView: UITableView) -> Int {
        return 1
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return checkInLists?.count ?? 0
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: SelectCheckInListTableViewController.reuseIdentifier, for: indexPath)
        if let checkInList = checkInList(for: indexPath) {
            cell.textLabel?.text = checkInList.name
        }
        return cell
    }

    private func checkInList(for indexPath: IndexPath) -> CheckInList? {
        guard let checkInLists = checkInLists else { return nil }
        guard checkInLists.count > indexPath.row else { return nil }
        return checkInLists[indexPath.row]
    }

    // MARK: View Communication
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let selectedCell = sender as? UITableViewCell, let selectedIndexPath = tableView.indexPath(for: selectedCell),
           let selectedCheckInList = checkInList(for: selectedIndexPath), let event = self.event, let eventSettings = self.eventSettings {
            configStore?.set(event: event, eventSettings: eventSettings, checkInList: selectedCheckInList)
        }
    }
}
