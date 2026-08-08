import Foundation
@testable import BSVBigNum
import Testing

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

private let bigNumScaleTestsEnabled =
    ProcessInfo.processInfo.environment["BSV_BIG_NUM_SCALE"] == "1"

@Suite("Big-number scale gates", .serialized)
struct BigNumScaleTests {
    @Test(
        "750 KB and 32 MiB import/export remain linear and bounded",
        .enabled(if: bigNumScaleTestsEnabled)
    )
    func importExportScale() throws {
        // Warm fixed allocator/runtime overhead before measuring input-scaled
        // resident growth. This keeps the four-times ceiling about the value,
        // not first-use test-runner and malloc arena initialization.
        let warmup = try BigMagnitude(bigEndian: [1], maximumByteCount: 1)
        _ = try warmup.bigEndianBytes(maximumByteCount: 1)

        let postGenesisLimit = 750_000
        let chronicleLimit = 32 * 1_024 * 1_024
        for byteCount in [
            postGenesisLimit - 1,
            postGenesisLimit,
            chronicleLimit - 1,
            chronicleLimit,
        ] {
            var input = Array(repeating: UInt8(0), count: byteCount)
            input[0] = 0x80
            let baseline = currentResidentBytes()

            let importStart = ContinuousClock.now
            let value = try BigMagnitude(
                bigEndian: input,
                maximumByteCount: byteCount
            )
            let importDuration = importStart.duration(to: .now)
            #expect(importDuration <= .seconds(8))
            #expect(value.byteCount == byteCount)
            try expectResidentDelta(
                from: baseline,
                maximum: byteCount * 4
            )

            let exportStart = ContinuousClock.now
            let output = try value.bigEndianBytes(maximumByteCount: byteCount)
            let exportDuration = exportStart.duration(to: .now)
            #expect(exportDuration <= .seconds(8))
            #expect(output == input)
            try expectResidentDelta(
                from: baseline,
                maximum: byteCount * 4
            )
        }
    }

    @Test(
        "Limit plus one rejects before dependency construction",
        .enabled(if: bigNumScaleTestsEnabled)
    )
    func limitPlusOne() {
        let limit = 32 * 1_024 * 1_024
        let input = Array(repeating: UInt8(0x01), count: limit + 1)
        let baseline = currentResidentBytes()
        var constructed = false

        let caught: BigNumError?
        do {
            _ = try BigMagnitude(
                bigEndian: input,
                maximumByteCount: limit,
                constructionObserver: { constructed = true }
            )
            caught = nil
        } catch let error as BigNumError {
            caught = error
        } catch {
            caught = nil
        }
        let current = currentResidentBytes()

        #expect(caught == .inputTooLarge(actual: limit + 1, maximum: limit))
        #expect(!constructed)
        if let baseline, let current {
            // Allocator and test-runner noise are calibrated to one MiB.
            #expect(max(0, current - baseline) <= 1_024 * 1_024)
        }
    }

    private func expectResidentDelta(from baseline: Int?, maximum: Int) throws {
        guard let baseline, let current = currentResidentBytes() else { return }
        let delta = max(0, current - baseline)
        #expect(delta <= maximum)
    }
}

private func currentResidentBytes() -> Int? {
#if canImport(Darwin)
    var information = mach_task_basic_info()
    var count = mach_msg_type_number_t(
        MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size
    )
    let status = withUnsafeMutablePointer(to: &information) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(
                mach_task_self_,
                task_flavor_t(MACH_TASK_BASIC_INFO),
                $0,
                &count
            )
        }
    }
    guard status == KERN_SUCCESS else { return nil }
    return Int(information.resident_size)
#elseif canImport(Glibc)
    guard let text = try? String(contentsOfFile: "/proc/self/statm", encoding: .utf8),
          let residentPages = text.split(separator: " ").dropFirst().first,
          let pages = Int(residentPages)
    else {
        return nil
    }
    return pages * Int(sysconf(Int32(_SC_PAGESIZE)))
#else
    return nil
#endif
}
