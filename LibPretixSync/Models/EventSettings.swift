//
//  EventSettings.swift
//  pretixSCAN
//
//  Created by Q Misell on 16.07.25.
//

import Foundation
import FMDB

public enum UICId {
    case int(UInt)
    case ia5(String)
}

public struct EventSettings: Model {
    public static let humanReadableName = "Event Settings"
    public static let stringName = "settings"

    public let settings: [String: Any?]
    
    static var searchByEventQuery = """
    SELECT * FROM "\(stringName)" WHERE event=?;
    """
    
    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: AnyCodable.CodingKeys.self) {
            var result = [String: Any?]()
            for key in container.allKeys {
                result[key.stringValue] = try container.decode(AnyCodable.self, forKey: key).value
            }
            settings = result
        } else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Event settings must be a dictionary"))
        }
    }
    
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: AnyCodable.CodingKeys.self)
        for key in self.settings.keys {
            if let val = self.settings[key] {
                try container.encode(AnyCodable(val), forKey: AnyCodable.CodingKeys(stringValue: key)!)
            } else {
                try container.encodeNil(forKey: AnyCodable.CodingKeys(stringValue: key)!)
            }
        }
    }
    
    static func from(result: FMResultSet, in database: FMDatabase) -> EventSettings? {
        guard let json = result.string(forColumn: "json"), let jsonData = json.data(using: .utf8) else { return nil }
        guard let settings = try? JSONDecoder.iso8601withFractionsDecoder.decode(EventSettings.self, from: jsonData) else { return nil }

        return settings
    }
    
    var scan_uic_barcode: Bool {
        settings["scan_uic_barcode"] as? Bool ?? false
    }
    
    var uic_public_key: String? {
        settings["uic_public_key"] as? String
    }
    
    var uic_security_provider: UICId? {
        if let id = settings["uic_security_provider"] as? UInt {
            return .int(id)
        } else if let id = settings["uic_security_provider"] as? String {
            return .ia5(id)
        } else {
            return nil
        }
    }
    
    var uic_key_id: UICId? {
        if let id = settings["uic_key_id"] as? UInt {
            return .int(id)
        } else if let id = settings["uic_key_id"] as? String {
            return .ia5(id)
        } else {
            return nil
        }
    }
}

extension EventSettings: Equatable {
    public static func == (lhs: EventSettings, rhs: EventSettings) -> Bool {
        return false
    }
}

extension EventSettings: Hashable {
    public func hash(into hasher: inout Hasher) {
        
    }
}

private struct AnyCodable: Encodable, Decodable {
    public var value: Any?
    
    struct CodingKeys: CodingKey {
        var stringValue: String
        var intValue: Int?
        init?(intValue: Int) {
            self.stringValue = "\(intValue)"
            self.intValue = intValue
        }
        init?(stringValue: String) { self.stringValue = stringValue }
    }
    
    init<T>(_ wrapped: T) {
        self.value = wrapped
    }

    public init(from decoder: Decoder) throws {
        if let container = try? decoder.container(keyedBy: CodingKeys.self) {
          var result = [String: Any?]()
          try container.allKeys.forEach { (key) throws in
            result[key.stringValue] = try container.decode(AnyCodable.self, forKey: key).value
          }
          value = result
        } else if var container = try? decoder.unkeyedContainer() {
            var result = [Any?]()
            while !container.isAtEnd {
              result.append(try container.decode(AnyCodable.self).value)
            }
            value = result
        } else if let container = try? decoder.singleValueContainer() {
            if let uintVal = try? container.decode(UInt.self) {
              value = uintVal
            } else if let intVal = try? container.decode(Int.self) {
              value = intVal
            } else if let doubleVal = try? container.decode(Double.self) {
              value = doubleVal
            } else if let boolVal = try? container.decode(Bool.self) {
              value = boolVal
            } else if let stringVal = try? container.decode(String.self) {
            value = stringVal
            } else {
              value = nil
            }
        } else {
            throw DecodingError.dataCorrupted(DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Could not serialise"))
        }
    }
    
    public func encode(to encoder: any Encoder) throws {
        if let map = self.value as? [String: Any] {
            var container = encoder.container(keyedBy: CodingKeys.self)
            for k in map.keys {
                let value = map[k]
                try container.encode(AnyCodable(value), forKey: CodingKeys(stringValue: k)!)
            }
        } else if let arr = self.value as? [Any] {
            var container = encoder.unkeyedContainer()
            for value in arr {
                try container.encode(AnyCodable(value))
            }
        } else {
            var container = encoder.singleValueContainer()
            
            if let value = self.value as? String {
                try container.encode(value)
            } else if let value = self.value as? UInt {
                try container.encode(value)
            } else if let value = self.value as? Int {
                try container.encode(value)
            } else if let value = self.value as? Double {
                try container.encode(value)
            } else if let value = self.value as? Bool {
                try container.encode(value)
            } else {
                try container.encodeNil()
            }
        }
    }
}

