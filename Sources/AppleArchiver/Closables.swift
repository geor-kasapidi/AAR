protocol Closable {
    func close() throws
}

struct Closables {
    // MARK: Lifecycle

    fileprivate init(error: Swift.Error) {
        self.error = error
    }

    // MARK: Internal

    mutating func new<T: Closable>(_ body: () -> T?) throws -> T {
        guard let item = body() else {
            throw self.error
        }
        self.items.append(item)
        return item
    }

    func close() {
        for item in self.items.reversed() {
            try? item.close()
        }
    }

    // MARK: Private

    private let error: Swift.Error

    private var items: [Closable] = []
}

func withClosables<T>(error: Swift.Error, _ body: (inout Closables) throws -> T) throws -> T {
    var closables = Closables(error: error)

    let result = Result {
        try body(&closables)
    }

    closables.close()

    switch result {
    case let .success(success):
        return success
    case let .failure(failure):
        throw failure
    }
}
