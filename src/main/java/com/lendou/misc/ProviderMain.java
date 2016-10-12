package com.lendou.misc;

import sun.security.jca.Providers;

import java.security.Provider;

/**
 * 通用的主函数
 *
 * 所有 Provider 的操作也可以用 Security 类来实现
 */
public class ProviderMain {

    public static void main(String[] args) {
        for (Provider provider : Providers.getFullProviderList().providers()) {
            System.out.println(provider.getName() + "======================");
            int a = 0;
            for (Provider.Service service : provider.getServices()) {
                System.out.println(++a + "\t" + service.getAlgorithm());
            }
        }
    }
}
