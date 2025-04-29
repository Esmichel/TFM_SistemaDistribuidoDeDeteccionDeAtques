# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/sergio/esp/esp-idf/components/bootloader/subproject"
  "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader"
  "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix"
  "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix/tmp"
  "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix/src/bootloader-stamp"
  "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix/src"
  "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/sergio/Desktop/Repos/GithubRepos/TFM/TFM_SistemaDistribuidoDeDeteccionDeAtques/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
