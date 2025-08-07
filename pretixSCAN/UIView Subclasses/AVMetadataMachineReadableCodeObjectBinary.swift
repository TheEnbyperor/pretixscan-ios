//
//  AVMetadataMachineReadableCodeObjectBinary.swift
//  pretixSCAN
//
//  Created by Q Misell on 16.07.25.
//

import Foundation
import AVKit

extension AVMetadataMachineReadableCodeObject
{
    var binaryValue: Data?
    {
        switch type
        {
            case .qr:
                return removeQrProtocolData(binaryValueWithProtocol!)
            case .aztec:
                guard let string = stringValue else
                { return nil }
                return string.data(using: String.Encoding.isoLatin1)
            default:
                return nil
        }
    }

    var binaryValueWithProtocol: Data?
    {
        guard let descriptor = descriptor else
        {
            return nil
        }
        switch type
        {
            case .qr:
                return (descriptor as! CIQRCodeDescriptor).errorCorrectedPayload
            case .aztec:
                return (descriptor as! CIAztecCodeDescriptor).errorCorrectedPayload
            case .pdf417:
                return (descriptor as! CIPDF417CodeDescriptor).errorCorrectedPayload
            case .dataMatrix:
                return (descriptor as! CIDataMatrixCodeDescriptor).errorCorrectedPayload
            default:
                return nil
        }
    }

    private func removeQrProtocolData(_ input: Data) -> Data?
    {
        var halves = input.halfBytes()
        var batch = takeBatch(&halves)
        var output = batch
        while !batch.isEmpty
        {
            batch = takeBatch(&halves)
            output.append(contentsOf: batch)
        }
        return Data(output)
    }

    private func takeBatch(_ input: inout [HalfByte]) -> [UInt8]
    {
        let version = (descriptor! as! CIQRCodeDescriptor).symbolVersion
        let characterCountLength = version > 9 ? 16 : 8
        let mode = input.remove(at: 0)
        var output = [UInt8]()
        switch (mode.value)
        {
                // TODO If there is not only binary in the QRCode, then cases should be added here.
            case 0x04: // Binary
                let charactersCount: UInt16
                if characterCountLength == 8
                {
                    charactersCount = UInt16(input.takeUInt8())
                }
                else
                {
                    charactersCount = UInt16(input.takeUInt16())
                }
                for _ in 0..<charactersCount
                {
                    output.append(input.takeUInt8())
                }
                return output
            case 0x00: // End of data
                return []
            default:
                return []
        }
    }
}

fileprivate struct HalfByte
{
    let value: UInt8
}

fileprivate extension [HalfByte]
{
    mutating func takeUInt8() -> UInt8
    {
        let left = self.remove(at: 0)
        let right = self.remove(at: 0)
        return UInt8(left, right)
    }

    mutating func takeUInt16() -> UInt16
    {
        let first = self.remove(at: 0)
        let second = self.remove(at: 0)
        let third = self.remove(at: 0)
        let fourth = self.remove(at: 0)
        return UInt16(first, second, third, fourth)
    }
}

fileprivate extension Data
{
    func halfBytes() -> [HalfByte]
    {
        var result = [HalfByte]()
        self.forEach
            { (byte: UInt8) in result.append(contentsOf: byte.halfBytes()) }
        return result
    }

    init(_ halves: [HalfByte])
    {
        var halves = halves
        var result = [UInt8]()
        while halves.count > 1
        {
            result.append(halves.takeUInt8())
        }
        self.init(result)
    }
}

fileprivate extension UInt8
{
    func halfBytes() -> [HalfByte]
    {
        [HalfByte(value: self >> 4), HalfByte(value: self & 0x0F)]
    }

    init(_ left: HalfByte, _ right: HalfByte)
    {
        self.init((left.value << 4) + (right.value & 0x0F))
    }
}

fileprivate extension UInt16
{
    init(_ first: HalfByte, _ second: HalfByte, _ third: HalfByte, _ fourth: HalfByte)
    {
        let first = UInt16(first.value) << 12
        let second = UInt16(second.value) << 8
        let third = UInt16(third.value) << 4
        let fourth = UInt16(fourth.value) & 0x0F
        let result = first + second + third + fourth
        self.init(result)
    }
}
