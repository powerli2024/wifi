package android.system

/** API-shaped fake; errno is the only field production code retains. */
class ErrnoException(functionName: String, val errno: Int) : Exception(functionName)
