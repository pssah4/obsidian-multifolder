type LoggerLevel = 'debug' | 'warn' | 'error';

const LOG_PREFIX = '[Multifolder]';

function normalizeArgs(args: unknown[]): unknown[] {
    if (args.length === 0) {
        return [LOG_PREFIX];
    }

    const [first, ...rest] = args;
    if (typeof first === 'string') {
        if (first.startsWith('[Multifolder]') || first.startsWith('[Multifolder]')) {
            return args;
        }
        return [`${LOG_PREFIX} ${first}`, ...rest];
    }

    return [LOG_PREFIX, ...args];
}

function write(level: LoggerLevel, ...args: unknown[]): void {
    const logger = globalThis.console;
    const method = logger?.[level] ?? logger?.log;
    // Called through .call so the console keeps its own `this`; a detached
    // console method throws in some host environments.
    method?.call(logger, ...normalizeArgs(args));
}

export const logger = {
    debug: (...args: unknown[]) => write('debug', ...args),
    warn: (...args: unknown[]) => write('warn', ...args),
    error: (...args: unknown[]) => write('error', ...args),
};
