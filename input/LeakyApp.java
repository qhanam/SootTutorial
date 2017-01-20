public class LeakyApp {

	public static void main (String[] args) {
		
		LeakyApp app = new LeakyApp();
		String data = app.source();
		String formatted = "Data: " + data;
		app.sink(data);
		app.sink(formatted);

	}

	public LeakyApp() { }

	/**
	 * return some private information.
	 */
	public String source() {
		return "private-info";
	}

	/**
	 * Sends information in a non-private manner.
	 * @param data The information to send.
	 */
	public void sink(String data) {
		System.out.println(data);
	}

}
