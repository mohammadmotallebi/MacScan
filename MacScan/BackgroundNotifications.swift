import Foundation
import MacScanCore
import UserNotifications

private let sessionIDKey = "MacScan.sessionID"
private let sectionKey = "MacScan.section"

/// Tells the user that an app just got a sensitive permission. A click opens the Privacy section.
enum PermissionAlert {
    static func post(_ grant: PrivacyGrant) async {
        let content = UNMutableNotificationContent()
        content.title = "New permission"
        content.body = PermissionWatcher.message(for: grant)
        content.sound = .default
        content.userInfo = [sectionKey: "privacy"]
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        do {
            try await UNUserNotificationCenter.current().add(request)
        } catch {
            FileLogger.shared.warning("Could not post notification: \(error.localizedDescription)")
        }
    }
}

/// Delivers background-scan notifications through Notification Center. Used by the headless worker.
struct UserNotifier: BackgroundNotifying {
    func notify(_ notification: BackgroundNotification) async {
        let content = UNMutableNotificationContent()
        content.title = notification.title
        content.body = notification.body
        content.sound = .default
        if let id = notification.sessionID { content.userInfo = [sessionIDKey: id.uuidString] }
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        do {
            try await UNUserNotificationCenter.current().add(request)
        } catch {
            // Usually: notifications are off for MacScan in System Settings. The scan is still in History.
            FileLogger.shared.warning("Could not post notification: \(error.localizedDescription)")
        }
    }
}

enum NotificationPermission: Equatable {
    case allowed
    case denied
    case notAsked

    /// Asks once (macOS shows its own prompt the first time), then reports the current state.
    static func request() async -> NotificationPermission {
        let center = UNUserNotificationCenter.current()
        _ = try? await center.requestAuthorization(options: [.alert, .sound])
        return await current()
    }

    static func current() async -> NotificationPermission {
        switch await UNUserNotificationCenter.current().notificationSettings().authorizationStatus {
        case .authorized, .provisional: .allowed
        case .denied: .denied
        default: .notAsked
        }
    }
}

/// Opens the right scan in History when a background-scan notification is clicked.
@MainActor
final class NotificationRouter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationRouter()

    /// Set by `AppState`. A click that arrives before it exists waits in `pending`.
    var openSession: ((UUID) -> Void)? {
        didSet {
            if let openSession, let pending {
                self.pending = nil
                openSession(pending)
            }
        }
    }

    private var pending: UUID?

    /// Set by `AppState`: opens the Privacy section.
    var openPrivacy: (() -> Void)?

    func install() {
        UNUserNotificationCenter.current().delegate = self
    }

    private func route(_ id: UUID) {
        if let openSession { openSession(id) } else { pending = id }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        if response.notification.request.content.userInfo[sectionKey] as? String == "privacy" {
            await MainActor.run { NotificationRouter.shared.openPrivacy?() }
            return
        }
        guard let raw = response.notification.request.content.userInfo[sessionIDKey] as? String, let id = UUID(uuidString: raw) else { return }
        await MainActor.run { NotificationRouter.shared.route(id) }
    }

    /// Show the banner even when MacScan is the front app.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }
}
