"""
Bible verses utility for displaying inspirational verses on dashboards
"""
import random

# Collection of inspirational Bible verses
BIBLE_VERSES = [
    {
        "verse": "For I know the plans I have for you, declares the Lord, plans to prosper you and not to harm you, to give you hope and a future.",
        "reference": "Jeremiah 29:11"
    },
    {
        "verse": "I can do all things through Christ who strengthens me.",
        "reference": "Philippians 4:13"
    },
    {
        "verse": "Trust in the Lord with all your heart and lean not on your own understanding; in all your ways submit to him, and he will make your paths straight.",
        "reference": "Proverbs 3:5-6"
    },
    {
        "verse": "Be strong and courageous. Do not be afraid; do not be discouraged, for the Lord your God will be with you wherever you go.",
        "reference": "Joshua 1:9"
    },
    {
        "verse": "And we know that in all things God works for the good of those who love him, who have been called according to his purpose.",
        "reference": "Romans 8:28"
    },
    {
        "verse": "The Lord is my shepherd, I lack nothing. He makes me lie down in green pastures, he leads me beside quiet waters, he refreshes my soul.",
        "reference": "Psalm 23:1-3"
    },
    {
        "verse": "Cast all your anxiety on him because he cares for you.",
        "reference": "1 Peter 5:7"
    },
    {
        "verse": "But those who hope in the Lord will renew their strength. They will soar on wings like eagles; they will run and not grow weary, they will walk and not be faint.",
        "reference": "Isaiah 40:31"
    },
    {
        "verse": "The Lord your God is with you, the Mighty Warrior who saves. He will take great delight in you; in his love he will no longer rebuke you, but will rejoice over you with singing.",
        "reference": "Zephaniah 3:17"
    },
    {
        "verse": "Have I not commanded you? Be strong and courageous. Do not be afraid; do not be discouraged, for the Lord your God will be with you wherever you go.",
        "reference": "Joshua 1:9"
    },
    {
        "verse": "The Lord is close to the brokenhearted and saves those who are crushed in spirit.",
        "reference": "Psalm 34:18"
    },
    {
        "verse": "Come to me, all you who are weary and burdened, and I will give you rest.",
        "reference": "Matthew 11:28"
    },
    {
        "verse": "Do not be anxious about anything, but in every situation, by prayer and petition, with thanksgiving, present your requests to God.",
        "reference": "Philippians 4:6"
    },
    {
        "verse": "The name of the Lord is a fortified tower; the righteous run to it and are safe.",
        "reference": "Proverbs 18:10"
    },
    {
        "verse": "He gives strength to the weary and increases the power of the weak.",
        "reference": "Isaiah 40:29"
    },
    {
        "verse": "Therefore do not worry about tomorrow, for tomorrow will worry about itself. Each day has enough trouble of its own.",
        "reference": "Matthew 6:34"
    },
    {
        "verse": "The Lord will fight for you; you need only to be still.",
        "reference": "Exodus 14:14"
    },
    {
        "verse": "Blessed are the peacemakers, for they will be called children of God.",
        "reference": "Matthew 5:9"
    },
    {
        "verse": "Love is patient, love is kind. It does not envy, it does not boast, it is not proud.",
        "reference": "1 Corinthians 13:4"
    },
    {
        "verse": "In their hearts humans plan their course, but the Lord establishes their steps.",
        "reference": "Proverbs 16:9"
    },
    {
        "verse": "May the God of hope fill you with all joy and peace as you trust in him, so that you may overflow with hope by the power of the Holy Spirit.",
        "reference": "Romans 15:13"
    },
    {
        "verse": "Commit to the Lord whatever you do, and he will establish your plans.",
        "reference": "Proverbs 16:3"
    },
    {
        "verse": "The Lord is my light and my salvation—whom shall I fear? The Lord is the stronghold of my life—of whom shall I be afraid?",
        "reference": "Psalm 27:1"
    },
    {
        "verse": "Above all else, guard your heart, for everything you do flows from it.",
        "reference": "Proverbs 4:23"
    },
    {
        "verse": "Let us not become weary in doing good, for at the proper time we will reap a harvest if we do not give up.",
        "reference": "Galatians 6:9"
    },
    {
        "verse": "For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.",
        "reference": "John 3:16"
    },
    {
        "verse": "The Lord himself goes before you and will be with you; he will never leave you nor forsake you. Do not be afraid; do not be dismayed.",
        "reference": "Deuteronomy 31:8"
    },
    {
        "verse": "So don't worry about tomorrow, for tomorrow will worry about itself. Each day has enough trouble of its own.",
        "reference": "Matthew 6:34"
    },
    {
        "verse": "Wait for the Lord; be strong and take heart and wait for the Lord.",
        "reference": "Psalms 27:14"
    },
    {
        "verse": "For I know the plans I have for you, declares the Lord, plans to prosper you and not to harm you, to give you hope and a future.",
        "reference": "Jeremiah 29:11"
    }
]

def get_random_bible_verse():
    """
    Returns a random Bible verse from the collection
    
    Returns:
        dict: Dictionary containing 'verse' and 'reference' keys
    """
    return random.choice(BIBLE_VERSES)

def get_daily_bible_verse():
    """
    Returns a consistent Bible verse for the current day
    This ensures all users see the same verse on the same day
    
    Returns:
        dict: Dictionary containing 'verse' and 'reference' keys
    """
    import datetime
    
    # Use the current date as a seed for consistent daily verses
    today = datetime.date.today()
    seed = today.toordinal()  # Convert date to ordinal for consistent seeding
    
    # Create a new random instance with the date seed
    daily_random = random.Random(seed)
    return daily_random.choice(BIBLE_VERSES)
