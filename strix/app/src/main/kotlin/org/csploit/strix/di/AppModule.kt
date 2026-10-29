package org.csploit.strix.di

import android.content.Context
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import org.csploit.strix.data.bundle.BundleDownloader
import org.csploit.strix.data.bundle.BundleInstaller
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun bundleInstaller(@ApplicationContext context: Context): BundleInstaller =
        BundleInstaller(context.filesDir)

    @Provides
    @Singleton
    fun bundleDownloader(): BundleDownloader = BundleDownloader()
}
