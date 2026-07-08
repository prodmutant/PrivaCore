using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Diagnostics;
using PROSCANNERCONT.Models;
using PROSCANNERCONT.Utils;

namespace PROSCANNERCONT.Services
{
    public static class GalleryManager
    {
        private static readonly string GalleryFilePath = "gallery.json";
        private static ObservableCollection<GalleryItem> _galleryItems;

        public static ObservableCollection<GalleryItem> GalleryItems
        {
            get
            {
                if (_galleryItems == null)
                {
                    LoadGallery();
                }
                return _galleryItems;
            }
        }

        public static void AddScreenshot(GalleryItem item)
        {
            try
            {
                GalleryItems.Insert(0, item);
                SaveGallery();
                Debug.WriteLine($"Added screenshot to gallery: {item.Title}");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error adding screenshot to gallery: {ex.Message}");
            }
        }

        public static void RemoveScreenshot(GalleryItem item)
        {
            try
            {
                GalleryItems.Remove(item);
                SaveGallery();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error removing screenshot: {ex.Message}");
            }
        }

        private static void LoadGallery()
        {
            try
            {
                _galleryItems = new ObservableCollection<GalleryItem>();

                if (File.Exists(GalleryFilePath))
                {
                    string json = File.ReadAllText(GalleryFilePath);
                    if (!string.IsNullOrEmpty(json))
                    {
                        Debug.WriteLine($"Loading gallery from JSON: {json.Length} characters");

                        using var document = JsonDocument.Parse(json);
                        var itemsArray = document.RootElement.EnumerateArray();

                        int loadedCount = 0;
                        int screenshotSuccessCount = 0;
                        int screenshotFailCount = 0;

                        foreach (var itemElement in itemsArray.Take(100))
                        {
                            var item = new GalleryItem
                            {
                                Id = itemElement.GetProperty("Id").GetString() ?? Guid.NewGuid().ToString(),
                                Timestamp = itemElement.GetProperty("Timestamp").GetDateTime(),
                                Title = itemElement.GetProperty("Title").GetString() ?? "",
                                Description = itemElement.GetProperty("Description").GetString() ?? "",
                                PageType = itemElement.GetProperty("PageType").GetString() ?? "",
                                IsManual = itemElement.TryGetProperty("IsManual", out var isManualProp) ? isManualProp.GetBoolean() : false
                            };

                            // Load screenshot data - CRITICAL FIX
                            if (itemElement.TryGetProperty("ScreenshotData", out var screenshotDataProp))
                            {
                                var screenshotData = screenshotDataProp.GetString();
                                if (!string.IsNullOrEmpty(screenshotData))
                                {
                                    item.ScreenshotData = screenshotData;

                                    // Convert Base64 back to BitmapSource
                                    try
                                    {
                                        item.Screenshot = ScreenshotUtility.Base64ToBitmap(screenshotData);
                                        if (item.Screenshot != null)
                                        {
                                            screenshotSuccessCount++;
                                            Debug.WriteLine($"Successfully restored gallery screenshot for {item.Title}");
                                        }
                                        else
                                        {
                                            screenshotFailCount++;
                                            Debug.WriteLine($"Failed to convert Base64 to bitmap for {item.Title}");
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        screenshotFailCount++;
                                        Debug.WriteLine($"Error converting Base64 to bitmap for {item.Title}: {ex.Message}");
                                    }
                                }
                                else
                                {
                                    screenshotFailCount++;
                                    Debug.WriteLine($"Empty ScreenshotData for {item.Title}");
                                }
                            }
                            else
                            {
                                screenshotFailCount++;
                                Debug.WriteLine($"No ScreenshotData property found for {item.Title}");
                            }

                            _galleryItems.Add(item);
                            loadedCount++;
                        }

                        Debug.WriteLine($"Gallery LoadGallery Summary:");
                        Debug.WriteLine($"  - Total items loaded: {loadedCount}");
                        Debug.WriteLine($"  - Screenshots successfully restored: {screenshotSuccessCount}");
                        Debug.WriteLine($"  - Screenshots failed to restore: {screenshotFailCount}");
                    }
                    else
                    {
                        Debug.WriteLine("Gallery JSON file is empty");
                    }
                }
                else
                {
                    Debug.WriteLine("Gallery file does not exist - starting with empty gallery");
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error loading gallery: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                _galleryItems = new ObservableCollection<GalleryItem>();
            }
        }

        private static void SaveGallery()
        {
            try
            {
                var itemsToSave = GalleryItems.Take(100).Select(item => new
                {
                    item.Id,
                    item.Timestamp,
                    item.Title,
                    item.Description,
                    item.PageType,
                    item.IsManual,
                    item.ScreenshotData // CRITICAL: Include the Base64 screenshot data
                }).ToList();

                string json = JsonSerializer.Serialize(itemsToSave, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(GalleryFilePath, json);
                Debug.WriteLine($"Gallery saved successfully: {itemsToSave.Count} items, JSON size: {json.Length} characters");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error saving gallery: {ex.Message}");
                Debug.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        public static void ClearGallery()
        {
            try
            {
                GalleryItems.Clear();
                SaveGallery();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error clearing gallery: {ex.Message}");
            }
        }
    }
}
