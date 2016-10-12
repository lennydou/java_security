Algorithm Parameters Classes - 算法参数类

有些算法有初始化参数, 算法的初始化参数可以用AlgorithmParameter和AlgorithmParameterSpecs描述.
根据使用场景, 算法可以直接使用参数, 参数也可以被转成易携带的形式以便于传输或者存储.

AlgorithmParameters是一个引擎类, 提供加密参数的模糊表示. 可以使用AlgorithmParameterSpec初始化一个AlgorithmParameters。


// 创建一个算法参数
AlgorithmParameters.getInstance()

// 初始化AlgorithmParameters对象
void init(AlgorithmParameterSpec paramSpec)
void init(byte[] params)

Note: AlgorithmParameters对象只能被初始化一次, 不能复用